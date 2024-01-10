if __name__ == "__main__":

    actions = ['mitre_Collection', 'mitre_Command_and_Control', 'mitre_Credential_Access', 'mitre_Defense_Evasion', 'mitre_Discovery', 'mitre_Execution', 'mitre_Exfiltration', 'mitre_Impact', 'mitre_Initial_Access', 'mitre_Lateral_Movement', 'mitre_Persistence', 'mitre_Privilege_Escalation', 'mitre_Reconnaissance', 'mitre_Resource_Development']

    parser = argparse.ArgumentParser(description="Command wrapper for action.py HOC-CLI Script")
    parser.add_argument('-p', '--pid', type = int, help = "PID for process to monitor")
    parser.add_argument('-s','--source', type= str, help = "Source IP/Domain for Activity")
    parser.add_argument('-a', '--action', type= str, help = "MITRE Action for Activity: 'mitre_Collection', 'mitre_Command_and_Control', 'mitre_Credential_Access', 'mitre_Defense_Evasion', 'mitre_Discovery', 'mitre_Execution', 'mitre_Exfiltration', 'mitre_Impact', 'mitre_Initial_Access', 'mitre_Lateral_Movement', 'mitre_Persistence', 'mitre_Privilege_Escalation', 'mitre_Reconnaissance', 'mitre_Resource_Development'")
    parser.add_argument('-t', '--target', type= str, help = "Destination/Target Activity is being Conducted Against.")

    args = parser.parse_args()

    if args.action not in actions:
        print(f"Specified action: {args.action} is not a valid MITRE Action.")
        parser.print_help()
        exit()

    process = psutil.Process(args.pid)
    start_time = datetime.datetime.utcfromtimestamp(process.create_time()).isoformat(timespec="seconds")
    end_time = None

    print(f"Monitoring Process: {process.pid}")
    print(f"Process Command Line: {process.cmdline()}")
    while True:
        if not process.is_running():
            end_time = datetime.datetime.utcnow().isoformat(timespec="seconds")
            break

    print(f"Paste This into HOC CLI:")
    print(create_hoc_make_action_string(args.source, args.action, args.target, start_time, end_time, "success"))
