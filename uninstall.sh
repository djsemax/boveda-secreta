#!/bin/bash
# ============================================
#  Bóveda Secreta - Desinstalador
#  Creado por: djsemax
# ============================================

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║       BÓVEDA SECRETA                ║"
echo "  ║       Desinstalador                 ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${RED}  ⚠️  ATENCIÓN:${NC}"
echo "  Esto eliminará la aplicación y el lanzador."
echo "  Tus datos cifrados se encuentran en:"
echo "    ~/.local/share/.cache-visores"
echo ""
echo -n "  ¿Quieres eliminar TAMBIÉN tus datos cifrados? (si/no): "
read BORRAR_DATOS

echo -e "${YELLOW}[1/3] Eliminando lanzador...${NC}"
rm -f "$HOME/.local/share/applications/boveda-secreta.desktop"

echo -e "${YELLOW}[2/3] Eliminando aplicación...${NC}"
rm -f "$HOME/.local/bin/boveda.py"

echo -e "${YELLOW}[3/3] Limpiando configuración...${NC}"
rm -rf "$HOME/.config/.visor-notas"

if [ "$BORRAR_DATOS" = "si" ] || [ "$BORRAR_DATOS" = "SI" ] || [ "$BORRAR_DATOS" = "Sí" ]; then
    echo -e "${RED}  Eliminando datos cifrados...${NC}"
    rm -rf "$HOME/.local/share/.cache-visores"
    echo -e "${GREEN}  Datos eliminados.${NC}"
else
    echo -e "${YELLOW}  Datos conservados en ~/.local/share/.cache-visores${NC}"
fi

if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}  ✅ Desinstalación completada.${NC}"
echo ""
