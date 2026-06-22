#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  InScop3 Recon — Universal Linux Installer v3.1
#  Supports: Arch, Debian/Ubuntu, Fedora/RHEL, openSUSE, Kali, Parrot
# ─────────────────────────────────────────────────────────────────────────────
set -e
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${CYN}${BOLD}"
cat << 'BANNER'
 ___       ____  _____      ____     ____  ____   __
|_ _|     / ___||_   _|    |  _ \   / ___|/ __ \ / /|
 | |_____\___ \   | |      | |_) | | |   | |  | | | |
 | |_____ ___) |  | |      |  _ <  | |   | |_| | | |
|_|_____|____/   |_|      |_| \_\  \____|\___\_\\_\|
                InScop3 RECON — Comprehensive Reconnaissance Tool
BANNER
echo -e "${NC}"
echo -e "${BOLD}  Universal Linux Installer v3.1${NC}"

INSTALL_DIR="$HOME/.local/share/inscop3"
BIN_DIR="$HOME/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID,,}"        # lowercase
        DISTRO_LIKE="${ID_LIKE,,}" # e.g. "debian" for Ubuntu
    elif command -v lsb_release &>/dev/null; then
        DISTRO_ID="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
        DISTRO_LIKE=""
    else
        DISTRO_ID="unknown"
        DISTRO_LIKE=""
    fi
}

detect_distro
echo -e "${BLU}  Disztribúció: ${BOLD}${DISTRO_ID}${NC} ${DISTRO_LIKE:+(like: $DISTRO_LIKE)}"
echo -e "${BLU}  ────────────────────────────────────────────${NC}"
echo ""

# ── Package manager wrappers ──────────────────────────────────────────────────
pkg_install() {
    local pkg_arch="$1" pkg_deb="$2" pkg_fed="$3" pkg_suse="$4"
    case "$DISTRO_ID" in
        arch|manjaro|endeavouros|garuda|artix)
            sudo pacman -S --noconfirm --needed $pkg_arch 2>/dev/null || true ;;
        debian|ubuntu|kali|parrot|linuxmint|pop|raspbian|elementary)
            sudo apt-get install -y $pkg_deb 2>/dev/null || true ;;
        fedora|rhel|centos|rocky|alma|oracle)
            sudo dnf install -y $pkg_fed 2>/dev/null || \
            sudo yum install -y $pkg_fed 2>/dev/null || true ;;
        opensuse*|sles*)
            sudo zypper install -y $pkg_suse 2>/dev/null || true ;;
        *)
            if command -v pacman   &>/dev/null; then sudo pacman -S --noconfirm --needed $pkg_arch 2>/dev/null || true
            elif command -v apt-get &>/dev/null; then sudo apt-get install -y $pkg_deb 2>/dev/null || true
            elif command -v dnf    &>/dev/null; then sudo dnf install -y $pkg_fed 2>/dev/null || true
            elif command -v zypper  &>/dev/null; then sudo zypper install -y $pkg_suse 2>/dev/null || true
            fi ;;
    esac
}

pkg_update() {
    case "$DISTRO_ID" in
        arch|manjaro|endeavouros|garuda|artix)
            sudo pacman -Sy --noconfirm 2>/dev/null || true ;;
        debian|ubuntu|kali|parrot|linuxmint|pop|raspbian|elementary)
            sudo apt-get update -qq 2>/dev/null || true ;;
        fedora|rhel|centos|rocky|alma|oracle)
            sudo dnf check-update -q 2>/dev/null || true ;;
        opensuse*|sles*)
            sudo zypper refresh 2>/dev/null || true ;;
    esac
}

# ── 1. System packages ────────────────────────────────────────────────────────
echo -e "${BOLD}[1/6] Rendszercsomagok frissítése${NC}"
pkg_update

# pkg_install  arch            debian/ubuntu     fedora/rhel       opensuse
pkg_install    python          python3           python3           python3
pkg_install    python-pip      python3-pip       python3-pip       python3-pip
pkg_install    go              golang            golang            go
pkg_install    bind            dnsutils          bind-utils        bind-utils
pkg_install    nmap            nmap              nmap              nmap
pkg_install    curl            curl              curl              curl
pkg_install    wget            wget              wget              wget
pkg_install    ruby            ruby              ruby              ruby
# FIX 1: ruby-rdoc — csak ahol tényleg szükséges külön csomag (Debian/Ubuntu),
#         Arch-on a ruby csomag már tartalmazza, openSUSE-on is a ruby maga.
pkg_install    ruby            ruby-rdoc         ruby-doc          ruby

echo -e "  ${GRN}✓${NC} Rendszercsomagok kész"

# ── 2. PyQt6 ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[2/6] PyQt6${NC}"
if python3 -c "from PyQt6.QtWidgets import QApplication" 2>/dev/null; then
    echo -e "  ${GRN}✓${NC} PyQt6 már telepítve"
else
    echo -e "  ${YEL}→${NC} PyQt6 telepítése..."
    # FIX 2: Először mindig system package-et próbálunk; a --break-system-packages
    #         flag csak akkor kerül bevetésre, ha az is megbukik (pip fallback).
    PYQT_OK=false
    case "$DISTRO_ID" in
        arch|manjaro|endeavouros|garuda|artix)
            sudo pacman -S --noconfirm --needed python-pyqt6 2>/dev/null && PYQT_OK=true ;;
        debian|ubuntu|kali|parrot|linuxmint|pop|raspbian|elementary)
            sudo apt-get install -y python3-pyqt6 2>/dev/null && PYQT_OK=true ;;
        fedora|rhel|centos|rocky|alma|oracle)
            sudo dnf install -y python3-PyQt6 2>/dev/null && PYQT_OK=true ;;
        opensuse*|sles*)
            sudo zypper install -y python3-qt6 2>/dev/null && PYQT_OK=true ;;
    esac

    if [ "$PYQT_OK" = false ]; then
        echo -e "  ${YEL}→${NC} System package sikertelen, pip fallback..."
        pip3 install PyQt6 --break-system-packages -q 2>/dev/null || \
        pip  install PyQt6 --break-system-packages -q 2>/dev/null || true
    fi

    # Végső ellenőrzés
    if python3 -c "from PyQt6.QtWidgets import QApplication" 2>/dev/null; then
        echo -e "  ${GRN}✓${NC} PyQt6 kész"
    else
        echo -e "  ${RED}✗${NC} PyQt6 telepítés sikertelen — futtasd kézzel:"
        echo -e "     pip install PyQt6 --break-system-packages"
        exit 1
    fi
fi

# ── 3. Go PATH ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[3/6] Go PATH beállítás${NC}"
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$RC" ] && ! grep -q 'GOPATH/bin' "$RC" 2>/dev/null; then
        echo '' >> "$RC"
        echo '# Go binaries — InScop3 Recon' >> "$RC"
        echo 'export GOPATH="$HOME/go"' >> "$RC"
        echo 'export PATH="$PATH:$GOPATH/bin"' >> "$RC"
        echo -e "  ${GRN}✓${NC} Go PATH → $RC"
    fi
done

FISH_CFG="$HOME/.config/fish/config.fish"
if [ -f "$FISH_CFG" ] && ! grep -q 'GOPATH' "$FISH_CFG" 2>/dev/null; then
    echo '' >> "$FISH_CFG"
    echo '# Go binaries — InScop3 Recon' >> "$FISH_CFG"
    echo 'set -gx GOPATH $HOME/go' >> "$FISH_CFG"
    echo 'set -gx PATH $PATH $GOPATH/bin' >> "$FISH_CFG"
    echo -e "  ${GRN}✓${NC} Go PATH → $FISH_CFG (fish)"
fi
echo -e "  ${GRN}✓${NC} Go PATH kész"

# ── 4. ProjectDiscovery tools ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[4/6] ProjectDiscovery eszközök${NC}"
install_go_tool() {
    local name=$1 pkg=$2
    if command -v "$name" &>/dev/null || [ -f "$GOPATH/bin/$name" ]; then
        echo -e "  ${GRN}✓${NC} $name már telepítve"
    else
        echo -e "  ${YEL}→${NC} $name telepítése..."
        go install "$pkg" 2>&1 | tail -1
        if command -v "$name" &>/dev/null || [ -f "$GOPATH/bin/$name" ]; then
            echo -e "  ${GRN}✓${NC} $name kész"
        else
            echo -e "  ${RED}✗${NC} $name hiba — ellenőrizd: go install $pkg"
        fi
    fi
}
install_go_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool httpx      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool dnsx       "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool naabu      "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool nuclei     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

# ── 5. WhatWeb + WpScan ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[5/6] WhatWeb + WpScan${NC}"

# WhatWeb
if command -v whatweb &>/dev/null; then
    echo -e "  ${GRN}✓${NC} whatweb már telepítve"
else
    echo -e "  ${YEL}→${NC} WhatWeb telepítése..."
    WW_OK=false
    case "$DISTRO_ID" in
        arch|manjaro*) sudo pacman -S --noconfirm --needed whatweb 2>/dev/null && WW_OK=true ;;
        kali|parrot*)  sudo apt-get install -y whatweb 2>/dev/null && WW_OK=true ;;
        debian|ubuntu*) sudo apt-get install -y whatweb 2>/dev/null && WW_OK=true ;;
        fedora*)       sudo dnf install -y whatweb 2>/dev/null && WW_OK=true ;;
    esac
    [ "$WW_OK" = false ] && gem install whatweb 2>/dev/null || true
    command -v whatweb &>/dev/null \
        && echo -e "  ${GRN}✓${NC} whatweb kész" \
        || echo -e "  ${YEL}!${NC} whatweb — kézzel: gem install whatweb"
fi

# WpScan
if command -v wpscan &>/dev/null; then
    echo -e "  ${GRN}✓${NC} wpscan már telepítve"
else
    echo -e "  ${YEL}→${NC} WpScan telepítése..."
    WP_OK=false
    case "$DISTRO_ID" in
        kali|parrot*) sudo apt-get install -y wpscan 2>/dev/null && WP_OK=true ;;
    esac
    [ "$WP_OK" = false ] && gem install wpscan 2>/dev/null || true
    command -v wpscan &>/dev/null \
        && echo -e "  ${GRN}✓${NC} wpscan kész" \
        || echo -e "  ${YEL}!${NC} wpscan — kézzel: gem install wpscan"
fi

# ── 6. InScop3 telepítése ──────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[6/6] InScop3 telepítése${NC}"

# inscop3.py megléte ellenőrzés
if [ ! -f "$SCRIPT_DIR/inscop3.py" ]; then
    echo -e "  ${RED}✗${NC} Hiba: inscop3.py nem található itt: $SCRIPT_DIR"
    echo -e "     Bizonyosodj meg, hogy install_inscop3.sh és inscop3.py egy mappában vannak."
    exit 1
fi

mkdir -p "$INSTALL_DIR" "$BIN_DIR"
cp "$SCRIPT_DIR/inscop3.py" "$INSTALL_DIR/inscop3.py"
chmod +x "$INSTALL_DIR/inscop3.py"

cat > "$BIN_DIR/inscop3" << 'LAUNCHER'
#!/usr/bin/env bash
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"
exec python3 "$HOME/.local/share/inscop3/inscop3.py" "$@"
LAUNCHER
chmod +x "$BIN_DIR/inscop3"

if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        [ -f "$RC" ] && ! grep -q '.local/bin' "$RC" && \
            echo 'export PATH="$PATH:$HOME/.local/bin"' >> "$RC"
    done
fi

# Desktop entry
# FIX 3: Ha nincs icon.jpg, ne kerüljön érvénytelen útvonal a .desktop fájlba
DESK="$HOME/.local/share/applications"
mkdir -p "$DESK"

ICON_LINE="Icon=network-server"   # fallback: beépített rendszer-ikon
if [ -f "$SCRIPT_DIR/icon.jpg" ]; then
    cp "$SCRIPT_DIR/icon.jpg" "$INSTALL_DIR/icon.jpg"
    ICON_LINE="Icon=$INSTALL_DIR/icon.jpg"
    echo -e "  ${GRN}✓${NC} Ikon másolva"
else
    echo -e "  ${YEL}!${NC} icon.jpg nem található — rendszer fallback ikon lesz használva"
fi

cat > "$DESK/inscop3.desktop" << DESKTOP
[Desktop Entry]
Name=InScop3 Recon
Comment=Comprehensive Reconnaissance Tool
Exec=$BIN_DIR/inscop3
$ICON_LINE
Terminal=false
Type=Application
Categories=Network;Security;
Keywords=recon;reconnaissance;security;osint;
DESKTOP

echo -e "  ${GRN}✓${NC} Telepítve: $INSTALL_DIR/inscop3.py"
echo -e "  ${GRN}✓${NC} Launcher:  $BIN_DIR/inscop3"

# ── Összefoglaló ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BLU}────────────────────────────────────────────────────────${NC}"
echo -e "${GRN}${BOLD}  Telepítés kész!  [${DISTRO_ID}]${NC}"
echo ""
echo -e "  Indítás:    ${CYN}inscop3${NC}"
echo -e "  Vagy:       ${CYN}python3 ~/.local/share/inscop3/inscop3.py${NC}"
echo -e "  Frissítés:  ${CYN}cp inscop3.py ~/.local/share/inscop3/inscop3.py${NC}"
echo ""
echo -e "  ${YEL}Ha 'inscop3' nem található:${NC}"
echo -e "  ${CYN}source ~/.bashrc${NC}  /  ${CYN}source ~/.zshrc${NC}  /  nyiss új terminált"
echo ""
