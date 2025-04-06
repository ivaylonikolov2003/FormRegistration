from PIL import Image, ImageDraw, ImageFont
import io

def generate_captcha_image(text):
    img = Image.new("RGB", (100, 40), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    draw.text((10, 10), text, fill=(0, 0, 0), font=font)
    output = io.BytesIO()
    img.save(output, format="PNG")
    return output.getvalue()

def validate_captcha(input_text, expected_text):
    return input_text.strip().upper() == expected_text.upper()
