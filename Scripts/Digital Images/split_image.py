from PIL import Image
import sys

def split_rgb_channels(image_path):
    # Open the image
    img = Image.open(image_path)
    
    # Ensure the image is in RGB mode
    img = img.convert('RGB')
    
    # Split the image into R, G, B components
    r, g, b = img.split()
    
    # Save the individual channels
    r.save('red_channel.png')
    g.save('green_channel.png')
    b.save('blue_channel.png')
    
    return r, g, b

# Example usage:
image_path = sys.argv[1]
r, g, b = split_rgb_channels(image_path)
