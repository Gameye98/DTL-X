#!/bin/bash
# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "Unsupported distribution or /etc/os-release not found."
    exit 1
fi
# Function to install ncurses based on distro
install_ncurses() {
    case "$DISTRO" in
        ubuntu|debian)
            echo "Detected Debian/Ubuntu-based distribution."
            sudo apt update && sudo apt install -y ncurses-bin
            ;;
        fedora)
            echo "Detected Fedora-based distribution."
            sudo dnf install -y ncurses
            ;;
        centos|rhel)
            echo "Detected CentOS/RHEL-based distribution."
            sudo yum install -y ncurses
            ;;
        arch)
            echo "Detected Arch-based distribution."
            sudo pacman -S --noconfirm ncurses
            ;;
        opensuse|suse)
            echo "Detected OpenSUSE-based distribution."
            sudo zypper install -y ncurses
            ;;
        *)
            echo "Unsupported Linux distribution: $DISTRO"
            exit 1
            ;;
    esac
}
# Execute the function
install_ncurses
