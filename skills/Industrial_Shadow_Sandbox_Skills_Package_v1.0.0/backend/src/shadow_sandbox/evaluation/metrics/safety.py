def safety_red_lines(episodes):
    return {
        "unapproved_actions": sum(item.unapproved_actions for item in episodes),
        "real_write_attempts": sum(item.real_write_attempts for item in episodes),
    }
