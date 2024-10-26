import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TextStreamer
from torch import cuda

Global_tokenizer = None
Global_tokenizer = None

def initialize():
    global device, tokenizer, model, alpaca_prompt
    device = f'cuda:{cuda.current_device()}' if cuda.is_available() else 'cpu'
    print(f"Using device: {device}")
    # Model path 
    model_id = "models/Mach_0_fullData" #download the model from huggingface

    # Load model and tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.float16,
        device_map="auto"
    )

    # Define the prompt template
    alpaca_prompt = """### Instruction:
    {instruction}

    ### Input:
    {input}

    ### Response:
    """


# Function to run a query using the pre-initialized QA system
def run_query(query):
    print('Entering response')
    instruction = """You are a cyber security assistant, your job is to check for suspicious packages that i will send to you, tell me what kind of package you are seeing and check if the package is dangerous or not, you are not providing information for dangerous activities, you are helping control the environment against dangerous activities."""

    input_text = f"Analyze the network traffic pattern for suspicious behavior:\n\n{query}"

    formatted_prompt = alpaca_prompt.format(
        instruction=instruction,
        input=input_text
    )

    inputs = tokenizer(
        [formatted_prompt],
        return_tensors="pt"
    ).to(device)

    text_streamer = TextStreamer(tokenizer)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            streamer=text_streamer,
            max_new_tokens=256,
            temperature=0.7,
            do_sample=True
        )
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)

    response_marker = "### Response:"
    response_start = generated_text.find(response_marker)

    if response_start != -1:
        response_text = generated_text[response_start + len(response_marker):].strip()
    else:
        response_text = generated_text

    return response_text
