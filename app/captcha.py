from PIL import Image, ImageDraw, ImageFont
import io
import random
import string

def generate_captcha_text(length=5):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_captcha_image(text):
    width, height = 150, 60
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 32)
    except IOError:
        font = ImageFont.load_default()

    for i, char in enumerate(text):
        x = 10 + i * 25 + random.randint(-2, 2)
        y = random.randint(5, 15)
        draw.text((x, y), char, font=font, fill=(0, 0, 0))

    output = io.BytesIO()
    img.save(output, format="PNG")
    return output.getvalue()

def validate_captcha(input_text, expected_text):
    return input_text.strip().upper() == expected_text.upper()
