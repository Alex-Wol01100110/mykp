import typing


def underscore_to_whitespace(input_text: str) -> str:
    """
    Summary:
        Replace underscore to whitespace.

    Args:
        input (str): input text

    Returns:
        str: output text
    """
    return input_text.replace("_", " ")

def any_to_str(input_list: typing.Any) -> str:
    """
    Summary:
        Convert any to string.

    Args:
        input_list (typing.Any): input

    Returns:
        str: output
    """
    if (isinstance(input_list, list) or isinstance(input_list, tuple)) and len(
        input_list
    ) > 0:
        return str(input_list[0])
    return str(input_list)
