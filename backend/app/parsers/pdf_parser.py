from io import BytesIO

from pypdf import PdfReader


def parse_pdf(data: bytes) -> str:
    reader = PdfReader(BytesIO(data))

    return "\n\n".join(
        text
        for page in reader.pages
        if (text := page.extract_text())
    )
