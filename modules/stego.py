import os
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

try:
    from stegano import lsb
except ImportError:
    lsb = None

console = Console()


class StegoEngine:
    def check_dependencies(self):
        if lsb is None:
            console.print(
                "[bold red][!] Missing dependency: stegano[/bold red]")
            console.print(
                "[white]Run: /opt/davoid/venv/bin/pip install stegano[/white]")
            return False
        return True

    def hide_data(self):
        console.print(
            "[dim]Note: LSB Steganography works best with lossless formats like .png[/dim]")
        image_path = questionary.text(
            "Path to cover image (e.g., /tmp/innocent.png):", style=Q_STYLE).ask()

        if not image_path or not os.path.exists(image_path):
            console.print("[red][!] Image not found.[/red]")
            return

        secret_data = questionary.text(
            "Payload/Code to embed:", style=Q_STYLE).ask()
        if not secret_data:
            return

        output_path = questionary.text(
            "Output path for the modified image (e.g., hidden.png):", style=Q_STYLE).ask()

        with console.status("[cyan]Embedding data into image footprint...[/cyan]", spinner="bouncingBar"):
            try:
                secret_image = lsb.hide(image_path, secret_data)
                secret_image.save(output_path)
                console.print(
                    f"[bold green][+] Payload successfully hidden inside {output_path}[/bold green]")
            except Exception as e:
                console.print(
                    f"[bold red][!] Error embedding data:[/bold red] {e}")

    def extract_data(self):
        image_path = questionary.text(
            "Path to image containing hidden payload:", style=Q_STYLE).ask()

        if not image_path or not os.path.exists(image_path):
            console.print("[red][!] Image not found.[/red]")
            return

        with console.status("[cyan]Extracting data from image...[/cyan]", spinner="bouncingBar"):
            try:
                clear_message = lsb.reveal(image_path)
                if clear_message:
                    console.print(
                        Panel(clear_message, title="Extracted Payload", border_style="green"))
                else:
                    console.print(
                        "[yellow][!] No hidden data found in this image. (Or it was compressed/modified)[/yellow]")
            except Exception as e:
                console.print(
                    f"[bold red][!] Error extracting data (Image might not contain LSB payload):[/bold red] {e}")

    def run(self):
        draw_header("Steganography Engine (Data Hiding)")

        if not self.check_dependencies():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        while True:
            choice = questionary.select(
                "Select Steganography Operation:",
                choices=[
                    "1. Embed Payload into Image (Encode)",
                    "2. Extract Payload from Image (Decode)",
                    "Back"
                ],
                style=Q_STYLE
            ).ask()

            if not choice or choice == "Back":
                break
            elif "Embed" in choice:
                self.hide_data()
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            elif "Extract" in choice:
                self.extract_data()
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_stego():
    StegoEngine().run()


if __name__ == "__main__":
    run_stego()
