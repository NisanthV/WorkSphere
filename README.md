• Engineered secure REST API with JWT authentication 
• Designed relational database schemas for organizational 
hierarchies 
• Implemented efficient data operations using Django ORM  
• Frontend served as API consumer (MVP ReactJS)

# CycleGAN Image Converter

This repository implements a web-based interface for CycleGAN, enabling users to convert images between two domains using state-of-the-art Generative Adversarial Networks (GANs). The project is built with Django and PyTorch, and provides a user-friendly platform for uploading images, running them through pre-trained CycleGAN models, and viewing the results in a gallery.

## Features

- Image-to-Image Translation: Convert images between two distinct domains (e.g., SAR ↔ Optical) using CycleGAN.
- Web Interface: Simple and modern web UI built with Django templates and custom CSS for image upload, conversion, history, and user authentication.
- Pre-trained Models: The backend loads pre-trained CycleGAN generator weights for both A→B and B→A translation directions.
- User Accounts & History: Users can register, log in, and view a history of their image conversions.


## Getting Started

### Prerequisites

- Python 3.8+
- pip (Python package manager)
- [PyTorch](https://pytorch.org/) (install for your platform)
- Django 5.x

Installation

1. Clone the repository
    ```bash
    git clone https://github.com/NisanthV/cycleGAN.git
    cd cycleGAN
    ```

3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Download Pre-trained Models:
    - Place `latest_net_G_A.pth` and `latest_net_G_B.pth` CycleGAN generator weights in the `myapp/models/` directory.

5. Run Migrations:
    ```bash
    python manage.py migrate
    ```

6. Start the Development Server:
    ```bash
    python manage.py runserver
    ```

7. Access the Web App:
    - Open your browser and go to `http://127.0.0.1:8000/`


**Author:** [NisanthV](https://github.com/NisanthV)
