from PIL import Image, ImageDraw, ImageFont
import io
import random
import string

def generate_captcha_text(length=5):
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=length))

def generate_captcha_image(text):
    image_width = 150
    image_height = 60
    background_color = (255, 255, 255)
    text_color = (0, 0, 0)

    image = Image.new("RGB", (image_width, image_height), background_color)
    draw = ImageDraw.Draw(image)

    try:
        font = ImageFont.truetype("arial.ttf", 32)
    except IOError:
        font = ImageFont.load_default()

    for i, char in enumerate(text):
        x = 10 + i * 25 + random.randint(-2, 2)
        y = random.randint(5, 15)
        draw.text((x, y), char, font=font, fill=text_color)

    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()

def validate_captcha(user_input, correct_text):
    return user_input.strip().upper() == correct_text.upper()
