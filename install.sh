#!/bin/bash
# ============================================
#  Bóveda Secreta - Instalador
#  Creado por: djsemax
# ============================================

set -e

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║       BÓVEDA SECRETA v0.4.0          ║"
echo "  ║       Instalador para Linux          ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Comprobar que estamos en Linux Mint / Ubuntu / Debian
if ! command -v apt &> /dev/null; then
    echo -e "${RED}Este instalador requiere apt (Debian/Ubuntu/Linux Mint).${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/5] Actualizando repositorios...${NC}"
sudo apt update -y

echo -e "${YELLOW}[2/5] Instalando dependencias...${NC}"
sudo apt install -y \
    python3 \
    python3-gi \
    gir1.2-gtk-3.0 \
    python3-cryptography \
    gir1.2-poppler-0.18 \
    gir1.2-gstreamer-1.0 \
    gir1.2-gst-plugins-base-1.0 \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly \
    gstreamer1.0-libav \
    gstreamer1.0-pulseaudio

echo -e "${YELLOW}[3/5] Copiando la aplicación...${NC}"
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/boveda.py" "$INSTALL_DIR/boveda.py"
chmod +x "$INSTALL_DIR/boveda.py"

echo -e "${YELLOW}[4/5] Creando lanzador del menú...${NC}"
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR"

cat > "$APPS_DIR/boveda-secreta.desktop" << EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Bóveda Secreta
Comment=Gestor de archivos cifrados con perfiles
Exec=python3 $INSTALL_DIR/boveda.py
Icon=dialog-password
Terminal=false
Categories=Utility;Security;
StartupNotify=false
EOF

chmod +x "$APPS_DIR/boveda-secreta.desktop"

echo -e "${YELLOW}[5/5] Actualizando base de datos de aplicaciones...${NC}"
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}  ✅ Instalación completada.${NC}"
echo ""
echo "  Para abrir la app:"
echo "    - Búscala en el menú como 'Bóveda Secreta'"
echo "    - O ejecuta en terminal: python3 ~/.local/bin/boveda.py"
echo ""
echo -e "${YELLOW}  ⚠️  Si es la primera vez que la usas, se creará un perfil.${NC}"
echo ""

