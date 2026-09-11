[English](README.md) | [简体中文](README_CN.md) | [繁體中文](README_TW.md) | **Türkçe** | [Português (Brasil)](README_PT-BR.md) | [한국어](README_KO.md) | [Français](README_FR.md) | [Bahasa Indonesia](README_ID.md) | [Русский](README_RU.md) | [Українська](README_UA.md) | [ภาษาไทย](README_TH.md) | [Tiếng Việt](README_VI.md) | [Italiano](README_IT.md) | [Polski](README_PL.md) | [Български](README_BG.md) | [日本語](README_JA.md) | [Español](README_ES.md)

---

<div align="center">
  <img src="/assets/kernelsu_next.png" width="96" alt="KernelSU Next Logo">

  <h2>KernelSU Next</h2>
  <p><strong>Android cihazlar için çekirdek tabanlı bir root çözümüdür.</strong></p>

  <p>
    <a href="https://github.com/KernelSU-Next/KernelSU-Next/releases/latest">
      <img src="https://img.shields.io/github/v/release/KernelSU-Next/KernelSU-Next?label=Release&logo=github" alt="Latest Release">
    </a>
    <a href="https://nightly.link/KernelSU-Next/KernelSU-Next/workflows/build-manager-ci/next/Manager">
      <img src="https://img.shields.io/badge/Nightly%20Release-gray?logo=hackthebox&logoColor=fff" alt="Nightly Build">
    </a>
    <a href="https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html">
      <img src="https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu" alt="License: GPL v2">
    </a>
    <a href="/LICENSE">
      <img src="https://img.shields.io/github/license/KernelSU-Next/KernelSU-Next?logo=gnu" alt="GitHub License">
    </a>
    <a title="Crowdin" target="_blank" href="https://crowdin.com/project/kernelsu-next"><img src="https://badges.crowdin.net/kernelsu-next/localized.svg"></a>
  </p>
</div>

---

## 🚀 Özellikler

- Çekirdek tabanlı `su` ve root erişim yönetimi.
- [Magic Mount](https://topjohnwu.github.io/Magisk/details.html#magic-mount)** ve [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS) tabanlı modül sistemi.
- [Uygulama Profili](https://kernelsu.org/guide/app-profile.html): Uygulama başına root yetkisini sınırlandırma.

---

## ✅ Uyumluluk

KernelSU Next, **4.4 ile 6.6** arasındaki Android çekirdeklerini destekler.

| Çekirdek Sürümü      | Destek Notları                                                      |
|----------------------|---------------------------------------------------------------------|
| 5.10+ (GKI 2.0)      | Hazır imajlar ve LKM/KMI desteği                                    |
| 4.19 – 5.4 (GKI 1.0) | KernelSU sürücüsünün çekirdeğe gömülü olması gerekir                |
| < 4.14 (EOL)         | KernelSU sürücüsü gerekir (3.18+ deneysel olup yama gerektirebilir) |

**Desteklenen mimariler:** `arm64-v8a`, `armeabi-v7a`, `x86_64`

> [!CAUTION]
> Yeni çekirdek sürümleri, KernelSU Next'nun çökmesine ve `x86_64` üzerinde kernel panic tetiklemesine neden olabilecek uyumsuz bir değişiklik uyguladı! Daha fazla bilgi için web sitesini kontrol edin!

---

## 📦 Kurulum
This is a **kernel-source integration** step for kernel developers (not an Android APK installation). From the root of your kernel source tree:

```bash
curl -LSs "https://raw.githubusercontent.com/MirahSyakilla/KSUN/susfs+nomount-hookless/kernel/setup.sh" | bash -
```

The script clones/updates this repository into `KernelSU-Next/`, symlinks `drivers/kernelsu`, and registers it in the drivers `Makefile`/`Kconfig`. Use `--cleanup` to revert.

Required defconfig:

```text
CONFIG_KSU=y
CONFIG_KSU_HOOK_CORE=y
CONFIG_KSU_TAMPER_SYSCALL_TABLE=y
CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y
CONFIG_KSU_HOOKLESS_SUSFS=y
CONFIG_KSU_HOOKLESS_NOMOUNT=y
# CONFIG_KPROBES is not set
# CONFIG_KRETPROBES is not set
```

KPROBES/KRETPROBES are **not required** by the hookless configuration; the canonical technical reference is the [English README](README.md).
## 🏅 Güvenlik
- To report security issues, see [SECURITY.md](/SECURITY.md).
## 📜 Lisans

- **`/kernel` dizini:** [Yalnızca GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- **Diğer tüm dosyalar:** [GPL-3.0-veya-sonrası](https://www.gnu.org/licenses/gpl-3.0.html).

---

## 🙏 Katkıda Bulunanlar

- [Kernel-Assisted Superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/) – KernelSU Fikrinin temeli
- [Magisk](https://github.com/topjohnwu/Magisk) – Temel root altyapısı
- [Genuine](https://github.com/brevent/genuine/) – APK v2 imza doğrulaması
- [Diamorphine](https://github.com/m0nad/Diamorphine) – Rootkit teknikleri
- [KernelSU](https://github.com/tiann/KernelSU) – KernelSU Next'in temelini oluşturan orijinal proje
- [Magic Mount Port](https://github.com/5ec1cff/KernelSU/blob/main/userspace/ksud/src/magic_mount.rs) – KernelSU’yu kurtardığı için 💜 5ec1cff’e teşekkürler
