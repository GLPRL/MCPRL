import os

from mcp.server.fastmcp import FastMCP
"""
    Sticky notes example:
    from https://www.youtube.com/watch?v=-8k9lGpGQ6g
"""
mcp = FastMCP("AI Sticky Notes")
#Give some sticky notes and AI will store it in some external storage, for ex. - notepad file.

# tool: does something. like scrape, get data about indicator, etc.
# resource: like HTTP GET. exposing data, context or memory, anything that's retrieving data.
# Add a prompt: template for LLM interactions

NOTES_FILE = os.path.join(os.path.dirname(__file__), "notes.txt")

#validate file exists
def ensure_file():
    if not os.path.exists(NOTES_FILE):
        with open(NOTES_FILE, "w") as f:
            f.write("")

#given a message and return some string
@mcp.tool()
def add_note(message: str) -> str:
    """
        Append a new note to a sticky note file
        args:
            message(str): the noted content to be added
        return:
            str: confirmation message indicating note was saved
    """
    ensure_file()
    with open(NOTES_FILE, "a") as f:
        f.write(message + "\n")
    return "Note saved"

@mcp.tool()
def read_notes() -> str:
    """
        Read and return all notes from the sticky note file
        :returns:
            str: all notes as a single string seperated by line breaks.
            If no notes exists, a default message is returned.
    :return:
    """
    ensure_file()
    with open(NOTES_FILE, "r") as f:
        content = f.read().strip()
    return content or "No notes yet."

@mcp.resource("notes://latest")
def get_latest_note() -> str:
    """
    Get the latest note from the notes file.
    :return:
        A string that represents the latest note
    """
    ensure_file()
    with open(NOTES_FILE, "r") as f:
        lines = f.readline().strip()
    return lines[-1].strip() if lines else "No notes yet."

@mcp.prompt()
def notes_summary_prompt() -> str:
    """
    Generate a prompt asking the AI to summarize all current notes
    :return:
        str: a prompt string that includes all notes and asks for a summary
        if no notes exist, a message will be shown indicating that.
    """
    ensure_file()
    with open(NOTES_FILE, "r") as f:
        contents = f.read().strip()
    if not content:
        return "There are no notes yet"
    return f"Summarize the current notes: {content}"