systemadm_files = files('systemadm.vala',
                        'systemd-interfaces.vala')
systemadm = executable('systemadm', systemadm_files,
                       dependencies: [gtk3, gee, posix],
                       install: true)
install_data('systemadm.desktop', install_dir: applicationsdir)
install_data('systemadm.appdata.xml', install_dir: appdatadir)

sgapa_files = files('gnome-ask-password-agent.vala')
sgapa = executable('systemd-gnome-ask-password-agent', sgapa_files,
                   dependencies: [gtk3, gee, gio_unix, libnotify, posix],
                   install: true)
install_data('systemd-gnome-ask-password-agent.rules', install_dir: polkitrulesdir)
sgapa_units = files('systemd-gnome-ask-password-agent.path',
                    'systemd-gnome-ask-password-agent.service')
install_data(sgapa_units, install_dir: polkitrulesdir)
