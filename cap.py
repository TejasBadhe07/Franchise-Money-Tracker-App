import pyautogui
import time

def toggle_caps_lock():
    pyautogui.press('capslock')

if __name__ == "__main__":
    try:
        while True:
            toggle_caps_lock()
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nCaps Lock toggling stopped.")
