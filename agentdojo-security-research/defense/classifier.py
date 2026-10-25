class LightweightIntentClassifier:
    def __init__(self):
        # Initialize any necessary parameters or models here
        pass

    def classify(self, provenance_record):
        """
        Classify the intent of a tool call based on the provenance record.

        Args:
            provenance_record (dict): A dictionary containing the user's request,
                                      proposed tool, and argument values.

        Returns:
            str: 'allow', 'block', or 'ask' based on the classification.
        """
        # Implement the classification logic here
        # Example logic (to be replaced with actual implementation):
        user_request = provenance_record['user_request']
        proposed_tool = provenance_record['proposed_tool']
        arguments = provenance_record['arguments']

        # Placeholder logic for classification
        if self.is_valid_request(user_request, proposed_tool, arguments):
            return 'allow'
        else:
            return 'block'

    def is_valid_request(self, user_request, proposed_tool, arguments):
        """
        Check if the proposed tool call is valid based on the user's request.

        Args:
            user_request (str): The user's original request.
            proposed_tool (str): The tool being proposed for the call.
            arguments (dict): The arguments for the tool call.

        Returns:
            bool: True if the request is valid, False otherwise.
        """
        # Implement validation logic here
        return True  # Placeholder return value

    def explain_decision(self, decision):
        """
        Provide an explanation for the classification decision.

        Args:
            decision (str): The classification decision ('allow', 'block', or 'ask').

        Returns:
            str: Explanation for the decision.
        """
        explanations = {
            'allow': "The proposed call matches the user's request.",
            'block': "The proposed call does not match the user's request.",
            'ask': "The decision requires further clarification from the user."
        }
        return explanations.get(decision, "No explanation available.")