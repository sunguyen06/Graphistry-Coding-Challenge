import pandas as pd
from collections import deque  # for BFS

def trace_suspicious_activity(start_user_id, access_logs, activity_logs):
    # Initialize queue and processed sets
    queue = deque([start_user_id])
    processed_users, processed_cpus = set(), set()

    # Initialize results
    event_queue_log = []
    affected_users, affected_cpus = set(), set()

    # Perform a BFS
    while queue:
        current_user = queue.popleft()
        event_queue_log.append(f"Processing user: {current_user}")

        # Skip already processed users
        if current_user in processed_users:
            continue

        processed_users.add(current_user)

        # Find computers accessed by the current user
        user_computers = activity_logs[activity_logs["user_id"] == current_user]["computer_id"].unique()

        for cpu in user_computers:
            if cpu not in processed_cpus:
                processed_cpus.add(cpu)
                affected_cpus.add(cpu)
                event_queue_log.append(f"User {current_user} accessed computer {cpu}")

            # Find any other affected users on this computer
            users_on_computer = access_logs[access_logs["computer_id"] == cpu]["affected_user_id"].unique()
            for user in users_on_computer:
                if user not in processed_users:
                    affected_users.add(user)
                    queue.append(user)
                    event_queue_log.append(f"Computer {cpu} affected user {user}")
    
    return event_queue_log, affected_users, affected_cpus

def main():
    # Load CSV files
    access_logs = pd.read_csv("access_logs.csv")
    activity_logs = pd.read_csv("activity_logs.csv")

    # Start with a suspicious user ID
    start_user_id = "U1"

    # Execute the tracing function
    event_log, affected_users, affected_computers = trace_suspicious_activity(
        start_user_id, access_logs, activity_logs
    )

    # Format the output
    formatted_output = {
        "Event Log": event_log,
        "Summary": {
            "Total Affected Users": len(affected_users),
            "Total Affected Computers": len(affected_computers),
            "Affected Users": list(affected_users),
            "Affected Computers": list(affected_computers),
        },
    }

    # Save outputs to files
    with open("event_log.txt", "w") as f:
        f.write("\n".join(event_log))
    pd.DataFrame({
        "Metric": ["Total Affected Users", "Total Affected Computers"],
        "Count": [len(affected_users), len(affected_computers)],
    }).to_csv("summary.csv", index=False)

    # Display summary on the console
    print("Summary:")
    print(f"Total Affected Users: {len(affected_users)}")
    print(f"Total Affected Computers: {len(affected_computers)}")
    print("Event log saved to 'event_log.txt'. Summary saved to 'summary.csv'.")

if __name__ == "__main__":
    main()
