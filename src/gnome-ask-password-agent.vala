/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

using Gee;
using Gtk;
using GLib;
using Posix;

[CCode (cheader_filename = "time.h")]
extern int clock_gettime(int id, out timespec ts);

public class PasswordDialog : Dialog {

        public Entry entry;

        public PasswordDialog(string domain, string message, string icon) {
                set_title("%s Password".printf(domain));
                set_border_width(8);
                set_default_response(ResponseType.OK);
                set_icon_name(icon);

                add_button("_Cancel", ResponseType.CANCEL);
                add_button("_OK", ResponseType.OK);

                Container content = (Container) get_content_area();

                Box hbox = new Box(Orientation.HORIZONTAL, 16);
                hbox.set_border_width(8);
                content.add(hbox);

                Image image = new Image.from_icon_name(icon, IconSize.DIALOG);
                hbox.pack_start(image, false, false);

                Box vbox = new Box(Orientation.VERTICAL, 8);
                hbox.pack_start(vbox, true, true);

                Label label = new Label(message);
                vbox.pack_start(label, false, false);

                entry = new Entry();
                entry.set_visibility(false);
                entry.set_activates_default(true);
                vbox.pack_start(entry, false, false);

                entry.activate.connect(on_entry_activated);

                show_all();
        }

        public void on_entry_activated() {
                response(ResponseType.OK);
        }
}

class Watch : GLib.Object {
        File directory;
        FileMonitor file_monitor;

        private weak Application app;

        string title;
        string domain_display;
        string domain;

        public Watch(Application gapp, string domain, string path) throws GLib.Error {
                app = gapp;

                directory = File.new_for_path(path);
                file_monitor = directory.monitor_directory(0);
                file_monitor.changed.connect(file_monitor_changed);

                domain_display = "%s%s".printf(domain.ascii_up(1), domain.substring(1));
                title = "Password Request (%s)".printf(domain_display);
                this.domain = domain;

                look_in_directory(directory);
        }

        void look_in_directory(File dir) throws GLib.Error {
                FileEnumerator enumerator = dir.enumerate_children("standard::name", FileQueryInfoFlags.NOFOLLOW_SYMLINKS);

                FileInfo i;
                while ((i = enumerator.next_file()) != null) {
                        if (!i.get_name().has_prefix("ask.")) {
                                continue;
                        }

                        load_password(dir.get_child(i.get_name()));
                }
        }

        void file_monitor_changed(GLib.File file, GLib.File? other_file, GLib.FileMonitorEvent event_type) {
                if (!file.get_basename().has_prefix("ask.")) {
                        return;
                }

                if (event_type == FileMonitorEvent.CREATED ||
                    event_type == FileMonitorEvent.DELETED) {
                        try {
                                load_password(file);
                        } catch (Error e) {
                                show_error(e.message);
                        }
                }
        }

        bool load_password(File file) throws GLib.Error {
                KeyFile key_file = new KeyFile();
                int timeout = 5000;
                string socket;
                string message;
                string icon;

                try {
                        timespec ts;

                        key_file.load_from_file(file.get_path(), KeyFileFlags.NONE);

                        string not_after_as_string = key_file.get_string("Ask", "NotAfter");

                        clock_gettime(1, out ts);
                        uint64 now = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);

                        uint64 not_after = uint64.parse(not_after_as_string);;
                        if ((not_after == 0 && GLib.errno == Posix.EINVAL) ||
                            (not_after == int64.MAX && GLib.errno == Posix.ERANGE)) {
                                return false;
                        }

                        if (not_after > 0 && not_after < now) {
                                return false;
                        }

                        if (not_after > 0) {
                                timeout = (int)(not_after - now) / 1000;
                        }

                        socket = key_file.get_string("Ask", "Socket");
                } catch (GLib.Error e) {
                        return false;
                }

                try {
                        message = key_file.get_string("Ask", "Message").compress();
                } catch (GLib.Error e) {
                        message = "Please Enter %s Password!".printf(domain_display);
                }

                try {
                        icon = key_file.get_string("Ask", "Icon");
                } catch (GLib.Error e) {
                        icon = "dialog-password";
                }

                GLib.Notification n = new GLib.Notification(title);
                n.set_category("password.request." + domain);
                n.set_body(message);
                n.set_priority(GLib.NotificationPriority.NORMAL);
                n.set_icon(new ThemedIcon(icon));
                n.add_button_with_target("Enter password", "app.password-request", "(ssss)", domain, message, icon, socket);

                string n_id = "password-request-%s".printf(socket);
                app.send_notification(n_id, n);
                uint s = GLib.Timeout.add_once(timeout, () => {
                        app.withdraw_notification(n_id);
                        app.timeouts.unset(socket);
                });
                app.timeouts[socket] = s;

                return true;
        }
}

void show_error(string e) {
        Posix.stderr.printf("%s\n", e);
        var m = new MessageDialog(null, 0, MessageType.ERROR, ButtonsType.CLOSE, "%s", e);
        m.run();
        m.destroy();
}

class Application : Gtk.Application {
        private static bool system = false;
        private static bool user = false;

        private Watch? system_watch = null;
        private Watch? user_watch = null;

        public Gee.HashMap<string, uint> timeouts;

        private const OptionEntry entries[] = {
                { "system", 's', OptionFlags.NONE, OptionArg.NONE, ref system, "Watch for system requests", null },
                { "user", 'u', OptionFlags.NONE, OptionArg.NONE, ref user, "Watch for system requests", null },
                { null }
        };

        private const GLib.ActionEntry actions[] = {
                { "password-request", password_request, "(ssss)" },
        };

        public Application() {
                Object(application_id: "org.freedesktop.systemd.gnome-ask-password-agent",
                       flags: GLib.ApplicationFlags.IS_SERVICE);
                add_main_option_entries(entries);
                add_action_entries(actions, this);
                set_default(this);

                timeouts = new Gee.HashMap<string, uint>();
        }

        protected override void startup() {
                if (system) {
                        system_watch = add_watch("system", "/run/systemd/ask-password/");
                }

                if (user) {
                        string? xdg_runtime_dir = Environment.get_variable("XDG_RUNTIME_DIR");
                        if (xdg_runtime_dir == null) {
                                show_error("no user XDG runtime directory");
                        } else {
                                add_watch("user", (!) xdg_runtime_dir + "/systemd/ask-password/");
                        }
                }

                if (system_watch != null || user_watch != null) {
                        hold();
                } else {
                        show_error("no watches requested");
                }
        }

        private Watch? add_watch(string domain, string path) {
                try {
                        return new Watch(this, domain, path);
                } catch (IOError e) {
                        show_error("failed to set up %s watches on %s: %s".printf(domain, path, e.message));
                } catch (GLib.Error e) {
                        show_error("failed to set up %s watches on %s: %s".printf(domain, path, e.message));
                }

                return null;
        }

        private static void password_request(GLib.SimpleAction action, GLib.Variant? variant) {
                var gapp = GLib.Application.get_default();
                if (gapp == null) {
                        return;
                }
                var app = (Application) (!) gapp;

                if (variant.n_children() != 4) {
                        return;
                }

                string domain = variant.get_child_value(0).get_string();
                string message = variant.get_child_value(1).get_string();
                string icon = variant.get_child_value(2).get_string();
                string socket = variant.get_child_value(3).get_string();

                if (domain.length == 0 || message.length == 0 || icon.length == 0 || socket.length == 0) {
                        show_error("invalid password request (domain: '%s', message: '%s', icon: '%s', socket: '%s')".printf(domain, message, icon, socket));
                        return;
                }

                PasswordDialog password_dialog = new PasswordDialog(domain, message, icon);

                int result = password_dialog.run();
                string password = password_dialog.entry.get_text();
                password_dialog.destroy();

                uint n_id;
                if (app.timeouts.unset(socket, out n_id)) {
                        GLib.Source.remove(n_id);
                }

                if (result == ResponseType.REJECT ||
                    result == ResponseType.DELETE_EVENT ||
                    result == ResponseType.CANCEL) {
                        return;
                }

                Pid child_pid;
                int to_process;

                try {
                        Process.spawn_async_with_pipes(
                                        null,
                                        { "/usr/bin/pkexec", "/lib/systemd/systemd-reply-password", result == ResponseType.OK ? "1" : "0", socket },
                                        null,
                                        SpawnFlags.DO_NOT_REAP_CHILD,
                                        null,
                                        out child_pid,
                                        out to_process,
                                        null,
                                        null);
                        ChildWatch.add(child_pid, (pid, status) => {
                                Process.close_pid(pid);
                        });

                        OutputStream stream = new UnixOutputStream(to_process, true);
                        stream.write(password.data, null);
                } catch (Error e) {
                        show_error(e.message);
                }
        }

        public static int main(string[] args) {
                try {
                        Gtk.init_with_args(ref args, "[OPTION...]", entries, "systemd-ask-password-agent");
                } catch (GLib.Error e) {
                        Posix.stderr.printf("%s\n", e.message);
                        return 1;
                }
                Application app = new Application();
                return app.run(args);
        }
}
