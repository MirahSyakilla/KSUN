[English](README.md) | [简体中文](README_CN.md) | [繁體中文](README_TW.md) | [Türkçe](README_TR.md) | [Português (Brasil)](README_PT-BR.md) | [한국어](README_KO.md) | [Français](README_FR.md) | [Bahasa Indonesia](README_ID.md) | [Русский](README_RU.md) | **Українська** | [ภาษาไทย](README_TH.md) | [Tiếng Việt](README_VI.md) | [Italiano](README_IT.md) | [Polski](README_PL.md) | [Български](README_BG.md) | [日本語](README_JA.md) | [Español](README_ES.md)

---

<div align="center">
  <img src="/assets/kernelsu_next.png" width="96" alt="KernelSU Next Logo">

  <h2>KernelSU Next</h2>
  <p><strong>Рішення для root-прав на основі ядра для пристроїв Android.</strong></p>

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

## 🚀 Особливості

- Керування `su` та root-доступом на основі ядра.
- Модульна система на основі [Magic Mount](https://topjohnwu.github.io/Magisk/details.html#magic-mount) та [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS).
- [Профілі програм](https://kernelsu.org/guide/app-profile.html): Обмеження root-прав для кожної програми.

---

## ✅ Сумісність

KernelSU Next підтримує ядра Android від **4.4 до 6.6**.

| Версія ядра          | Примітки підтримки                                                                        |
|----------------------|-------------------------------------------------------------------------------------------|
| 5.10+ (GKI 2.0)      | Підтримує попередньо створені образи та LKM/KMI                                           |
| 4.19 – 5.4 (GKI 1.0) | Потрібен вбудований драйвер KernelSU                                                      |
| < 4.14 (EOL)         | Потрібен драйвер KernelSU (версія 3.18+ є експериментальною, може знадобитися портування) |

**Підтримувані архітектури:** `arm64-v8a`, `armeabi-v7a`, `x86_64`

---

## 📦 Встановлення
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
## 🏅 Безпека
- To report security issues, see [SECURITY.md](/SECURITY.md).
## 📜 Ліцензія

- **Каталог `/kernel`:** [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- **Усі інші файли:** [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

---

## 🙏 Подяки

- [Kernel-Assisted Superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/) – Натхнення для концепції
- [Magisk](https://github.com/topjohnwu/Magisk) – Топовий інструмент для root
- [Genuine](https://github.com/brevent/genuine/) – Перевірка підпису APK версії 2
- [Diamorphine](https://github.com/m0nad/Diamorphine) – Деякі навики RootKit
- [KernelSU](https://github.com/tiann/KernelSU) – Основа для KernelSU Next
- [Magic Mount Port](https://github.com/5ec1cff/KernelSU/blob/main/userspace/ksud/src/magic_mount.rs) – 💜 до 5ec1cff за збереження KernelSU
