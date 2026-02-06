from django import template

register = template.Library()

@register.filter
def file_icon(file_type):
    """
    Returns an emoji icon based on the file MIME type.
    """
    if not file_type:
        return '📄'
    
    file_type = file_type.lower()
    
    # Images
    if 'image' in file_type:
        return '🖼️'
    
    # PDF
    if 'pdf' in file_type:
        return '📕'
    
    # Text / Code
    if 'text' in file_type or 'json' in file_type or 'xml' in file_type:
        return '📝'
    
    # Word / Documents
    if 'word' in file_type or 'document' in file_type or 'msword' in file_type:
        return '📘'
    
    # Excel / Spreadsheets
    if 'excel' in file_type or 'sheet' in file_type or 'csv' in file_type:
        return '📊'
    
    # PowerPoint / Presentation
    if 'powerpoint' in file_type or 'presentation' in file_type:
        return '📙'
    
    # Archives
    if 'zip' in file_type or 'rar' in file_type or 'compressed' in file_type or 'tar' in file_type:
        return '📦'
    
    # Audio
    if 'audio' in file_type:
        return '🎵'
    
    # Video
    if 'video' in file_type:
        return '🎬'
        
    # Python
    if 'python' in file_type or 'x-python' in file_type:
        return '🐍'

    return '📄'
