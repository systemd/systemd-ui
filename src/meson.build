systemadm_files = files('systemadm.vala',
                        'systemd-interfaces.vala')
systemadm = executable('systemadm', systemadm_files,
                       dependencies: [common_flags, gtk3, gee, posix],
                       install: true)
install_data('io.systemd.systemadm.desktop', install_dir: applicationsdir)
install_data('io.systemd.systemadm.svg', install_dir: iconsdir)
install_data('io.systemd.systemadm.metainfo.xml', install_dir: metainfodir)

sgapa_files = files('gnome-ask-password-agent.vala')
sgapa = executable('systemd-gnome-ask-password-agent', sgapa_files,
                   dependencies: [common_flags, gtk3, gee, gio_unix, libnotify, posix],
                   install: true)
install_data('systemd-gnome-ask-password-agent.rules', install_dir: polkitrulesdir)
sgapa_units = files('systemd-gnome-ask-password-agent.path',
                    'systemd-gnome-ask-password-agent.service')
install_data(sgapa_units, install_dir: userunitdir)
