class BasePerms:
    """
    Base permissions class
    """
    def __init__(self, user, action_id, source_class):
        self.user = user
        self.source_class = source_class
        self.action_id = action_id
