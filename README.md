# 🔐 Bóveda Secreta

Una app de escritorio para Linux  que guarda tus archivos **cifrados** con contraseña, organizados en perfiles independientes. Ideal para quien tiene cosas que no quiere que vea el cuñado. 😏

![Versión](https://img.shields.io/badge/versión-0.4.0-blue)
![Plataforma](https://img.shields.io/badge/plataforma-Linux%20Mint%2021+-green)
![Licencia](https://img.shields.io/badge/licencia-MIT-yellow)
![Python](https://img.shields.io/badge/python-3.8+-orange)

---

## ✨ Características

- 🔒 **Cifrado AES-256-GCM** con clave derivada por PBKDF2 (600.000 iteraciones)
- 👤 **Perfiles múltiples**: cada perfil es una bóveda independiente con su propia contraseña
- 🎭 **Perfil fake**: muestra archivos inocentes para engañar a mirones (se activa con `ESC` o `Ctrl+F`)
- 🖼️ **Visor de imágenes** con zoom, navegación y arrastre
- 🎬 **Reproductor de vídeo** con sonido, play/pause, volumen y barra de progreso
- 📄 **Vista previa de PDF** (requiere Poppler)
- ⭐ **Favoritos y chincheta** para fijar archivos arriba
- 🔍 **Buscador** con filtros por tipo, favoritos y orden
- 📁 **Carpetas** con navegación y drag & drop
- 🎨 **Temas**: claro, oscuro, gris, monocromo
- 🖱️ **Minimiza a bandeja** con la tecla `ESC`
- 💫 **Ofuscación de imágenes**: difumina miniaturas para mayor privacidad
- 📤 **Importar / Exportar** archivos

---

## 📸 Capturas

> 🚧 Aquí irían tus capturas de pantalla.
> Te recomiendo añadir al menos 2 o 3:
> - La vista principal con archivos
> - El reproductor de vídeo
> - El perfil fake

---

## 🚀 Instalación rápida

### Opción 1: Un solo comando (recomendado)

```bash
git clone https://github.com/djsemax/boveda-secreta.git
cd boveda-secreta
./install.sh
