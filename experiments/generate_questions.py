
import json
import os

def generate_questions():
    """Generates a JSON file with 100 sample questions for testing."""
    # Base templates for questions
    templates = [
        "What does the document say about {topic}?",
        "Can you explain the policy on {topic}?",
        "How is {topic} handled in the system?",
        "What are the security implications of {topic}?",
        "Who is responsible for {topic}?",
        "Are there any restrictions on {topic}?",
        "What is the procedure for {topic}?",
        "Provide details regarding {topic}.",
        "Is there any mention of {topic}?",
        "Summarize the information on {topic}."
    ]

    topics = [
        "data privacy", "access control", "remote work", "vacation time", 
        "expense reimbursement", "cloud infrastructure", "password policies", 
        "incident response", "employee benefits", "software deployment"
    ]

    questions = []
    
    # Generate 100 questions (10 templates x 10 topics)
    for template in templates:
        for topic in topics:
            questions.append({
                "query": template.format(topic=topic),
                "collection_name": "hr_policy" # We can use a generic collection name, or vary it if needed.
            })

    output_path = os.path.join(os.path.dirname(__file__), 'test_questions.json')
    
    with open(output_path, 'w') as f:
        json.dump(questions, f, indent=4)
        
    print(f"Successfully generated {len(questions)} questions at {output_path}")

if __name__ == "__main__":
    generate_questions()
