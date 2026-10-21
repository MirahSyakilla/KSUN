use anyhow::{Context, Result, bail};
use goblin::elf::{Elf, section_header, sym::Sym};
use rustix::system::init_module;
use scroll::{Pwrite, ctx::SizeWith};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};

struct Kptr {
    value: String,
}

impl Kptr {
    pub fn new() -> Result<Self> {
        let value = fs::read_to_string("/proc/sys/kernel/kptr_restrict")?;
        fs::write("/proc/sys/kernel/kptr_restrict", "1")?;
        Ok(Kptr { value })
    }
}

impl Drop for Kptr {
    fn drop(&mut self) {
        let _ = fs::write("/proc/sys/kernel/kptr_restrict", self.value.as_bytes());
    }
}

pub struct KptrOwnedIter<I> {
    _kptr: Kptr,
    iter: I,
}

impl<I: Iterator> Iterator for KptrOwnedIter<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

pub fn kernel_symbols_iter() -> Result<impl Iterator<Item = (String, u64)>> {
    let kptr = Kptr::new()?;

    let iter = BufReader::new(File::open("/proc/kallsyms")?)
        .lines()
        // https://github.com/torvalds/linux/blob/7f87a5ea75f011d2c9bc8ac0167e5e2d1adb1594/kernel/kallsyms.c#L727
        // We can stop read as soon as we read all kernel symbols
        .map_while(|line| {
            line.ok().and_then(|line| {
                let mut splits = line.split_whitespace();
                splits
                    .next()
                    .and_then(|addr| u64::from_str_radix(addr, 16).ok())
                    .and_then(|addr| {
                        splits
                            .nth(1)
                            .take_if(|_| splits.next().is_none()) // stop at module symbols
                            .map(|symbol| {
                                (
                                    symbol
                                        .find("$")
                                        .or_else(|| symbol.find(".llvm."))
                                        .map(|pos| &symbol[0..pos])
                                        .unwrap_or(symbol)
                                        .to_owned(),
                                    addr,
                                )
                            })
                    })
            })
        });

    Ok(KptrOwnedIter { _kptr: kptr, iter })
}

pub fn for_each_kernel_symbols<F: FnMut(&(String, u64)) -> Result<bool>>(mut f: F) -> Result<()> {
    for item in kernel_symbols_iter()? {
        if !f(&item)? {
            break;
        }
    }
    Ok(())
}

type UndefinedSymbols = HashMap<String, (Sym, usize)>;

/// Collect the undefined symbols of an ELF kernel module, keyed by name, with
/// the file offset of each symbol table entry.
fn undefined_symbols(buffer: &[u8]) -> Result<(UndefinedSymbols, goblin::container::Ctx)> {
    let elf = Elf::parse(buffer)?;
    let ctx = *elf.syms.ctx();

    let mut unresolved_symbols: HashMap<String, (Sym, usize)> = HashMap::new();
    for (index, sym) in elf.syms.iter().enumerate() {
        if index == 0 {
            continue;
        }

        if sym.st_shndx != section_header::SHN_UNDEF as usize {
            continue;
        }

        let Some(name) = elf.strtab.get_at(sym.st_name) else {
            continue;
        };

        let offset = elf.syms.offset() + index * Sym::size_with(elf.syms.ctx());
        unresolved_symbols.insert(name.to_owned(), (sym, offset));
    }

    Ok((unresolved_symbols, ctx))
}

fn bind_symbol(
    buffer: &mut [u8],
    (mut sym, offset): (Sym, usize),
    addr: u64,
    ctx: goblin::container::Ctx,
) -> Result<()> {
    sym.st_shndx = section_header::SHN_ABS as usize;
    sym.st_value = addr;
    buffer.pwrite_with(sym, offset, ctx)?;
    Ok(())
}

/// Resolve `names` against /proc/kallsyms, one address per name. The first
/// match in kallsyms order wins.
pub fn resolve_kallsyms(names: &[&str]) -> Result<Vec<Option<u64>>> {
    let mut addrs = vec![None; names.len()];
    let mut pending: HashMap<&str, usize> = names
        .iter()
        .enumerate()
        .map(|(i, name)| (*name, i))
        .collect();

    if !pending.is_empty() {
        for_each_kernel_symbols(|(symbol, addr)| {
            if let Some(i) = pending.remove(symbol.as_str()) {
                addrs[i] = Some(*addr);
            }

            Ok(!pending.is_empty())
        })
        .context("Cannot parse kallsyms")?;
    }

    Ok(addrs)
}

/// Relocate undefined symbols in an ELF kernel module buffer using /proc/kallsyms,
/// then load it via init_module syscall.
pub fn load_module(data: &[u8], params: &CStr) -> Result<()> {
    load_module_with_resolver(data, params, resolve_kallsyms)
}

/// Relocate undefined symbols in an ELF kernel module buffer with `resolve`,
/// then load it via init_module syscall. `resolve` gets all undefined symbol
/// names at once and returns one address per name; symbols it does not know
/// are left undefined for the kernel to bind against its exports.
pub fn load_module_with_resolver<F>(data: &[u8], params: &CStr, resolve: F) -> Result<()>
where
    F: FnOnce(&[&str]) -> Result<Vec<Option<u64>>>,
{
    let mut buffer = data.to_vec();
    let (unresolved_symbols, ctx) = undefined_symbols(&buffer)?;

    if !unresolved_symbols.is_empty() {
        let names: Vec<&str> = unresolved_symbols.keys().map(String::as_str).collect();
        let addrs = resolve(&names).context("Cannot resolve symbols")?;
        if addrs.len() != names.len() {
            bail!(
                "Resolver returned {} addresses for {} symbols",
                addrs.len(),
                names.len()
            );
        }

        for (name, addr) in names.iter().zip(addrs) {
            match addr {
                Some(addr) => bind_symbol(&mut buffer, unresolved_symbols[*name], addr, ctx)?,
                None => log::warn!("Cannot find symbol: {}", name),
            }
        }
    }

    init_module(&buffer, params).context("init_module failed.")?;
    Ok(())
}

fn has_kernelsu_legacy() -> bool {
    use syscalls::{Sysno, syscall};
    let mut version = 0;
    const CMD_GET_VERSION: i32 = 2;
    unsafe {
        let _ = syscall!(
            Sysno::prctl,
            0xDEADBEEF,
            CMD_GET_VERSION,
            std::ptr::addr_of_mut!(version)
        );
    }

    log::info!("KernelSU version: {}", version);

    version != 0
}

fn has_kernelsu_v2() -> bool {
    use syscalls::{Sysno, syscall};
    const KSU_INSTALL_MAGIC1: u32 = 0xDEADBEEF;
    const KSU_INSTALL_MAGIC2: u32 = 0xCAFEBABE;
    const KSU_IOCTL_GET_INFO: u32 = 0x80104b02; // _IOR('K', 2, struct ksu_get_info_cmd)
    const KSU_IOCTL_GET_INFO_LEGACY: u32 = 0x80004b02; // _IOC(_IOC_READ, 'K', 2, 0)

    #[repr(C)]
    #[derive(Default)]
    struct GetInfoCmd {
        version: u32,
        flags: u32,
        features: u32,
        uapi_version: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct GetInfoLegacyCmd {
        version: u32,
        flags: u32,
        features: u32,
    }

    // Try new method: get driver fd using reboot syscall with magic numbers
    let mut fd: i32 = -1;
    unsafe {
        let _ = syscall!(
            Sysno::reboot,
            KSU_INSTALL_MAGIC1,
            KSU_INSTALL_MAGIC2,
            0,
            std::ptr::addr_of_mut!(fd)
        );
    }

    let version = if fd >= 0 {
        // New method: try to get version info via ioctl
        let mut cmd = GetInfoCmd::default();
        let version = unsafe {
            let ret = syscall!(Sysno::ioctl, fd, KSU_IOCTL_GET_INFO, &mut cmd as *mut _);

            match ret {
                Ok(_) => cmd.version,
                Err(_) => {
                    let mut cmd = GetInfoLegacyCmd::default();
                    match syscall!(
                        Sysno::ioctl,
                        fd,
                        KSU_IOCTL_GET_INFO_LEGACY,
                        &mut cmd as *mut _
                    ) {
                        Ok(_) => cmd.version,
                        Err(_) => 0,
                    }
                }
            }
        };

        unsafe {
            let _ = syscall!(Sysno::close, fd);
        }

        version
    } else {
        0
    };

    log::info!("KernelSU version: {}", version);

    version != 0
}

pub fn has_kernelsu() -> bool {
    has_kernelsu_v2() || has_kernelsu_legacy()
}
