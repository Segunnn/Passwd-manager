import subprocess
import dearpygui.dearpygui as dpg
from db import DataBase

# --- DearPyGui initial setup (kept at top of file) ---
dpg.create_context()
dpg.create_viewport(title="Passwd Manager", width=600, height=300)

# TODO FIX CHECK PASSWORD

authenticated = False
wndw = None  # will hold the tag name of main window ("main_window")


def resource_form(uuid: int, enabled: bool = True, default_value: dict = dict(), autoselect: bool = True):
    """This function just creates input form """
    def show_pass(sender, app_data, user_data):
        if dpg.get_item_label(f'show_password_button{uuid}') == '*':
            dpg.configure_item(f'password_input{uuid}', password=False)
            dpg.configure_item(f'show_password_button{uuid}', label='!')
        else:
            dpg.configure_item(f'password_input{uuid}', password=True)
            dpg.configure_item(f'show_password_button{uuid}', label='*')

    with dpg.group(horizontal=True):
        dpg.add_text("Site   ", tag=f"site_text{uuid}")
        dpg.add_input_text(default_value=default_value.get('name', ''),
                            enabled=enabled, tag=f"site_input{uuid}", hint='wtf.com',
                            auto_select_all=autoselect)
    with dpg.group(horizontal=True):
        dpg.add_text("Mail   ")
        dpg.add_input_text(default_value=default_value.get('mail', ''),
                            enabled=enabled, tag=f"mail_input{uuid}", hint='aaa@example.com',
                            auto_select_all=autoselect)
    with dpg.group(horizontal=True):
        dpg.add_text("Login  ")
        dpg.add_input_text(default_value=default_value.get('login', ''),
                            enabled=enabled, tag=f"login_input{uuid}", hint='MegaDestroyer3000',
                            auto_select_all=autoselect)
    with dpg.group(horizontal=True):
        dpg.add_text("Passwd ", tag=f"password_text{uuid}")
        dpg.add_input_text(default_value=default_value.get('password', ''),
                            enabled=enabled, tag=f"password_input{uuid}",
                            hint='qwerty123', password=True, auto_select_all=autoselect)
        shw_btn = dpg.add_button(label='*', callback=show_pass, tag=f"show_password_button{uuid}")
        with dpg.tooltip(shw_btn):
            dpg.add_text("Show password")
    with dpg.group(horizontal=True):
        dpg.add_text("Note   ")
        dpg.add_input_text(default_value=default_value.get('note', ''),
                            enabled=enabled, tag=f"note_input{uuid}", hint='?',
                            auto_select_all=autoselect)


def save_new_resource(form_uuid: int, modal_name: str):
    data = {
        'name': dpg.get_value(f"site_input{form_uuid}"),
        'mail': dpg.get_value(f"mail_input{form_uuid}"),
        'login': dpg.get_value(f"login_input{form_uuid}"),
        'passwd': dpg.get_value(f"password_input{form_uuid}"),
        'note': dpg.get_value(f"note_input{form_uuid}")
    }
    missing_color = [220, 82, 93]
    if data['name'] == '':
        dpg.configure_item(f"site_text{form_uuid}", color=missing_color)
        return None

    if data['passwd'] == '':
        dpg.configure_item(f"password_text{form_uuid}", color=missing_color)
        return None

    res = DataBase()
    res.add_resource(name=data['name'], login=data['login'], mail=data['mail'], note=data['note'], passwd=data['passwd'])
    refresh_resources()
    dpg.delete_item(modal_name)


def delete_resource(sender, app_data, user_data: tuple[int, int]):
    label = dpg.get_item_label(sender)
    res_db_id = user_data[1]
    if not label:
        return None

    if label[-1] == '!':
        res = DataBase()
        res.delete_resource(res_db_id)
        refresh_resources()
    else:
        dpg.configure_item(sender, label='Delete!')


def edit_resource(sender, app_data, form_uuid: int):
    get_data = lambda uuid: {
        'name': dpg.get_value(f"site_input{uuid}"),
        'mail': dpg.get_value(f"mail_input{uuid}"),
        'login': dpg.get_value(f"login_input{uuid}"),
        'password': dpg.get_value(f"password_input{uuid}"),
        'note': dpg.get_value(f"note_input{uuid}")
    }
    original_name = get_data(form_uuid)['name']

    def upd():
        db = DataBase()
        missing_color = [220, 82, 93]
        data = get_data(0)
        if data['name'] == '':
            dpg.configure_item(f"site_text{form_uuid}", color=missing_color)
            return None

        if data['password'] == '':
            dpg.configure_item(f"password_text{form_uuid}", color=missing_color)
            return None

        db.update_resource(name=original_name, new_name=data['name'],
                           login=data['login'], mail=data['mail'],
                           note=data['note'], passwd=data['password'])
        dpg.delete_item('edit_modal')
        refresh_resources()

    with dpg.window(label="Edit resource", modal=True, show=True,
                    width=300, height=180, tag="edit_modal",
                    on_close=lambda: dpg.delete_item("edit_modal"), ):
        resource_form(uuid=0, default_value=get_data(form_uuid), autoselect=False)
        with dpg.group(horizontal=True):
            dpg.add_button(label="Save", callback=upd)


def input_modal_window(sender=None, app_data=None, user_data=None):
    if dpg.does_item_exist('add_modal'):
        dpg.delete_item('add_modal')
    with dpg.window(label="New resource", modal=True, show=True,
                    width=300, height=180, tag="add_modal",
                    on_close=lambda: dpg.delete_item("add_modal")):
        resource_form(uuid=0)
        with dpg.group(horizontal=True):
            dpg.add_button(label="Save", callback=lambda: save_new_resource(0, 'add_modal'))


def refresh_resources():
    # Use the main window tag as parent if it exists
    parent = "main_window" if dpg.does_item_exist("main_window") else 0
    if dpg.does_item_exist("resources_container"):
        dpg.delete_item("resources_container")
    db = DataBase()
    resources = db.get_resources()

    with dpg.group(parent=parent, tag="resources_container"):
        for i, resource in enumerate(resources, start=1):  # uuid 0 reserved for modals/forms
            with dpg.collapsing_header(label=resource, tag=f"resource_header{i}"):
                info = db.get_resource_info(resource)
                resource_form(uuid=i, enabled=False, default_value=info)
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Edit", tag=f"edit_button{i}", callback=edit_resource, user_data=i)
                    dlt_btn = dpg.add_button(label="Delete", callback=delete_resource,
                                             user_data=(i, info.get('id')), tag=f"delete_buttton{i}")
                    with dpg.tooltip(dlt_btn):
                        dpg.add_text("Click this button 2 times to delete this resource")
                    dpg.bind_item_theme(dlt_btn, "RedButton")


# ---------- AUTHENTICATION ----------
def check_password_su(sender, app_data, user_data):
    """
    DearPyGui callback signature. Returns nothing; sets global `authenticated` on success.
    Uses sudo -S so password can be provided via stdin. Only closes the modal on success.
    """
    global authenticated

    username = dpg.get_value("username_input")
    password = dpg.get_value("userpass_input")

    # basic sanity
    if not username:
        dpg.set_value("auth_status", "Enter username")
        dpg.configure_item("auth_status", color=[255, 180, 0])
        return

    try:
        # sudo -S reads password from stdin; -u username runs command as that user
        cmd = ["sudo", "-S", "-u", username, "echo", "OK"]
        proc = subprocess.run(
            cmd,
            input=(password + "\n").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )

        out = proc.stdout.decode().strip()
        err = proc.stderr.decode().strip()

        if proc.returncode == 0 and out == "OK":
            authenticated = True
            dpg.delete_item("pass_modal")
            print("Authentication successful!")
        else:
            # show helpful feedback, don't close modal
            msg = "Authentication failed."
            # if sudo printed a message, include a short hint
            if err:
                msg += " " + err.splitlines()[0]
            dpg.set_value("auth_status", msg)
            dpg.configure_item("auth_status", color=[220, 82, 93])
            print("Auth failed:", proc.returncode, out, err)
    except subprocess.TimeoutExpired as e:
        dpg.set_value("auth_status", "Timeout (sudo took too long)")
        dpg.configure_item("auth_status", color=[220, 82, 93])
        print("Timeout:", e)
    except FileNotFoundError:
        dpg.set_value("auth_status", "sudo not found on system")
        dpg.configure_item("auth_status", color=[220, 82, 93])
        print("sudo not found")
    except Exception as e:
        dpg.set_value("auth_status", f"Error: {e}")
        dpg.configure_item("auth_status", color=[220, 82, 93])
        print("Auth error:", e)


def auth():
    with dpg.window(label="Password required", tag="pass_modal",
                    modal=True, show=True, no_close=True, width=380, height=140):
        dpg.add_text("User's password is required")
        #dpg.add_spacer(count=1)
        # username and password inputs; on_enter will call the check function
        dpg.add_input_text(tag="username_input", hint="username",
                           on_enter=True, callback=lambda s, a, u: dpg.focus_item('userpass_input'))
        dpg.add_input_text(password=True, tag="userpass_input",
                           on_enter=True, callback=check_password_su)
        #dpg.add_spacer(count=1)
        dpg.add_text("", tag="auth_status")  # will be updated with set_value()


def deploy_main_window():
    """
    Create the main window with a stable tag "main_window".
    """
    global wndw
    wndw = "main_window"
    with dpg.window(label="Main Window", tag=wndw):
        with dpg.menu_bar(parent=wndw):
            dpg.add_menu_item(label="Add", callback=input_modal_window)

        with dpg.theme(tag="RedButton"):
            with dpg.theme_component(dpg.mvButton):
                dpg.add_theme_color(dpg.mvThemeCol_Button, (237, 38, 81))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (173, 28, 59))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (150, 0, 0, 255))

        refresh_resources()

def main():
    global authenticated

    dpg.setup_dearpygui()
    dpg.show_viewport()
    auth()  # show the authentication modal first

    # main manual render loop (we handle showing main window after auth)
    while dpg.is_dearpygui_running():
        if authenticated and not dpg.does_item_exist("main_window"):
            deploy_main_window()
            dpg.set_primary_window("main_window", True)
        dpg.render_dearpygui_frame()

    dpg.destroy_context()


if __name__ == "__main__":
    main()

