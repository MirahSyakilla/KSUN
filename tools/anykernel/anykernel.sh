# AnyKernel3 Ramdisk Mod Script
# osm0sis @ xda-developers

## AnyKernel setup
# begin properties
properties() { '
kernel.string=MeowKernel by Meow
do.devicecheck=1
do.modules=0
do.systemless=0
do.cleanup=1
do.cleanuponabort=1
device.name1=lisa
supported.versions=
supported.patchlevels=
'; } # end properties

# shell variables
block=boot;
is_slot_device=1;
ramdisk_compression=auto;
patch_vbmeta_flag=auto;
no_block_display=1;

## AnyKernel methods (DO NOT CHANGE)
# import patching functions/variables - see for reference
. tools/ak3-core.sh;

# Read and print release version from version.txt
if [ -f "$AKHOME/version.txt" ]; then
  KERNEL_VERSION="$(sed -n '1p' "$AKHOME/version.txt")"
  if [ -n "$KERNEL_VERSION" ]; then
    ui_print "[?] Release Version: $KERNEL_VERSION"
  fi
else
  ui_print "[!] version.txt not found"
fi

## AnyKernel boot install
# Kernel + dtbo only: the package ships just `Image` and `dtbo.img`.
# No `dtb` file and no `vendor_ramdisk/` are present, so ak3-core.sh skips
# the vendor_boot setup entirely and vendor_boot is never repacked or
# flashed. The stock vendor_boot and the existing boot ramdisk are used
# as-is, which keeps the install seamless across ROM builds.
ui_print "[#] Installing Kernel and dtbo only...";
dump_boot;

write_boot;

ui_print "[+] Kernel successfully flashed!";
ui_print "[+] Thank you for using MeowKernel!";
## end boot install
