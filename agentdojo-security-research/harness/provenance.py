# This file handles the tracking and recording of provenance data during the execution of tasks.

class ProvenanceTracker:
    def __init__(self):
        self.provenance_data = []

    def record(self, task_id, tool_name, arguments, result):
        entry = {
            'task_id': task_id,
            'tool_name': tool_name,
            'arguments': arguments,
            'result': result
        }
        self.provenance_data.append(entry)

    def get_provenance_data(self):
        return self.provenance_data

    def clear_provenance_data(self):
        self.provenance_data = []