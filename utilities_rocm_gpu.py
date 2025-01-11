import re
import subprocess
import time

import pyrsmi.rocml as rocml


def get_rocm_smi_methods():
    # Initialize ROCm SMI
    rocml.smi_initialize()

    # List all attributes and methods in the rocml module
    attributes = dir(rocml)
    for attribute in attributes:
        print(attribute)

    # Shutdown ROCm SMI
    rocml.smi_shutdown()


def monitor_gpu_metrics(gpu_index=0, interval=1, iterations=10):
    """
    Monitor GPU metrics in a time loop.

    Parameters:
    - gpu_index (int): Index of the GPU to monitor.
    - interval (int): Time in seconds between each iteration.
    - iterations (int): Number of iterations to run the loop (use None for infinite loop).
    """
    try:
        # Initialize ROCm SMI
        rocml.smi_initialize()

        print(f"Monitoring GPU {gpu_index} metrics...")

        count = 0
        while iterations is None or count < iterations:
            # Fetch metrics
            # device_name = rocml.smi_get_device_name(gpu_index)
            # board_name = get_gpu_board_name()
            average_power = rocml.smi_get_device_average_power(gpu_index)
            total_memory = rocml.smi_get_device_memory_total(gpu_index) // (1024 * 1024)  # Convert to MB
            used_memory = rocml.smi_get_device_memory_used(gpu_index) // (1024 * 1024)  # Convert to MB
            fan_speed_max = rocml.smi_get_device_fan_speed_max(gpu_index)
            fan_speed_rpms = rocml.smi_get_device_fan_rpms(gpu_index)
            utilization_percent = rocml.smi_get_device_utilization(gpu_index)
            kernel_version = rocml.smi_get_kernel_version()

            # Fetch temperature and clock speeds using regex from sample output
            rocm_smi_output = subprocess.check_output(["rocm-smi", "--showtemp", "--showclocks"], text=True)
            # temperatures = extract_temperature(rocm_smi_output)
            # clock_speeds = extract_clock_speeds(rocm_smi_output)
            # performance_level = get_gpu_performance_level()
            # power_metrics = get_power_metrics()

            # Print metrics
            print(f"\nIteration {count + 1}:")
            # print(f"\tDevice Name: {board_name}")
            print(f"\tKernel Version: {kernel_version}")
            print(f"\tAverage Power: {average_power} W")
            print(f"\tTotal Memory: {total_memory} MB")
            print(f"\tUsed Memory: {used_memory} MB")
            print(f"\tMax Fan Speed: {fan_speed_max} RPM")
            print(f"\tFan Speed (RPM): {fan_speed_rpms}")
            print(f"\tUtilization: {utilization_percent}%")
            # print(f"\tTemperatures: {temperatures}")
            # print(f"\tClock Speeds: {clock_speeds}")
            # print(f"\tPerformance Level: {performance_level}")
            # print("\tPower Metrics:", power_metrics)

            # Wait for the specified interval
            time.sleep(interval)
            count += 1

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Finalize ROCm SMI
        rocml.smi_shutdown()
        print("Monitoring stopped and resources cleaned up.")


def get_gpu_info():
    """
    Retrieve GPU information, including the board name, VBIOS version, and power metrics.

    Returns:
    - dict: A dictionary containing the board name, VBIOS version, power usage, and power cap, or error messages if not found.
    """
    result = {}

    try:
        # Execute the rocm-smi command with multiple options
        output = subprocess.check_output(
            ["rocm-smi",
             "--showdriverversion",
             "--showvbios",
             "--showpower",
             "--showmaxpower",
             "--showtemp",
             "--showclocks",
             "--showperflevel",
             "--showuse",
             "--showmeminfo",
             "VRAM"
             ],
            text=True
        )

        # Retrieve board name using `clinfo | grep Board`
        try:
            board_output = subprocess.check_output("clinfo | grep Board", shell=True, text=True)
            board_match = re.search(r"Board name:\s+(.*)", board_output)
            if board_match:
                result["gpu_name"] = board_match.group(1).strip()
            else:
                result["gpu_name"] = "Not found in clinfo output."
        except subprocess.CalledProcessError as e:
            result["gpu_name"] = f"Error executing clinfo command: {e}"
        except Exception as e:
            result["gpu_name"] = f"Unexpected error: {e}"

        # Extract the driver version
        driver_match = re.search(r"Driver version:\s*([\d.]+)", output)
        if driver_match:
            result["driver_version"] = driver_match.group(1).strip()
        else:
            result["driver_version"] = "Driver version not found in rocm-smi output."

        # Extract the VBIOS version
        vbios_match = re.search(r"VBIOS version:\s+([\w-]+)", output)
        if vbios_match:
            result["vbios_version"] = vbios_match.group(1).strip()
        else:
            result["vbios_version"] = "VBIOS version not found in rocm-smi output."

        performance_level = re.search(r"Performance Level:\s+(.*)", output)
        if performance_level:
            result["p_state"] = performance_level.group(1)
        else:
            result["p_state"] = -1.0

        gpu_use_match = re.search(r"GPU\[\d]\s+:?\sGPU\suse\s\(%\):\s(\d)", output)
        if gpu_use_match:
            result["gpu_utilization"] = round(float(gpu_use_match.group(1)) / 100.0, 2)
        else:
            result["gpu_utilization"] = -1.0

        used_vram = re.search(r"GPU\[\d]\s+:?\sVRAM\sTotal\sUsed\sMemory\s\(B\):?\s(\d*)", output)
        if used_vram:
            result["memory_used"] = float(used_vram.group(1)) / (1024.0 * 1024.0)
        else:
            result["memory_used"] = -1.0

        total_vram = re.search(r"GPU\[\d]\s+:?\sVRAM\sTotal\sMemory\s\(B\):?\s(\d*)", output)
        if total_vram:
            result["memory_total"] = float(total_vram.group(1)) / (1024.0 * 1024.0)
        else:
            result["memory_total"] = -1.0

        if used_vram and total_vram:
            result["memory_utilization"] = round(float(result["memory_used"]) / float(result["memory_total"]), 2)
        else:
            result["memory_utilization"] = -1.0

        temp_match = re.search(r"Temperature \(Sensor edge\) \(C\): (\d+\.\d+)", output)
        if temp_match:
            result["temperature"] = round(float(temp_match.group(1)))
        else:
            result["temperature"] = -1.0

        # # Initialize ROCm SMI
        rocml.smi_initialize()

        fan_speed = rocml.smi_get_device_fan_speed(0)
        result["fan_speed"] = float(fan_speed)

        # Initialize ROCm SMI
        rocml.smi_shutdown()

        # Extract the power usage
        power_usage_match = re.search(r"Average Graphics Package Power \(W\):\s+([\d.]+)", output)
        if power_usage_match:
            result["power.draw"] = round(float(power_usage_match.group(1)))
        else:
            result["power.draw"] = -1.0

        # Extract the power cap
        power_cap_match = re.search(r"Max Graphics Package Power \(W\):\s+([\d.]+)", output)
        if power_cap_match:
            result["power.default_limit"] = round(float(power_cap_match.group(1)))
        else:
            result["power.default_limit"] = -1.0

        # Clock descriptions:
        # - dcefclk: Display Controller Engine Frequency Clock. Relates to display operations like driving monitors.(USE)
        # - fclk: Fabric Clock. Governs the Infinity Fabric, connecting GPU components and enabling data transfer.
        # - mclk: Memory Clock Speed. Represents the operational speed of the GPU's memory. (USE)
        # - sclk: Shader Clock (Graphics Clock). Controls the core GPU clock used for processing workloads. (USE)
        # - socclk: System on Chip Clock. Manages frequencies for other GPU subsystems like the video encoder/decoder.
        clock_match_dcefclk = re.search(r"dcefclk clock level: \d+: \((\d+)Mhz\)", output)
        if clock_match_dcefclk:
            result["clocks.video"] = round(float(clock_match_dcefclk.group(1)))
        else:
            result["clocks.video"] = -1.0

        clock_match_mclk = re.search(r"mclk clock level: \d+: \((\d+)Mhz\)", output)
        if clock_match_mclk:
            result["current_memory_clock"] = round(float(clock_match_mclk.group(1)))
        else:
            result["current_memory_clock"] = -1.0

        clock_match_sclk = re.search(r"sclk clock level: \d+: \((\d+)Mhz\)", output)
        if clock_match_sclk:
            result["current_graphics_clock"] = round(float(clock_match_sclk.group(1)))
            result["clocks.sm"] = round(float(clock_match_sclk.group(1)))
        else:
            result["current_graphics_clock"] = -1.0
            result["clocks.sm"] = -1.0

    except subprocess.CalledProcessError as e:
        error_message = f"Error executing rocm-smi command: {e}"
        print(error_message)
    except Exception as e:
        error_message = f"Unexpected error: {e}"
        print(error_message)

    return result


# Example usage
if __name__ == "__main__":
    # Method print
    # get_rocm_smi_methods()

    # Example usage
    # monitor_gpu_metrics(gpu_index=0, interval=5, iterations=5)

    print(get_gpu_info())