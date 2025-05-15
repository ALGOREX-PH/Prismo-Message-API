# Use the official Python image as a base image
FROM python:3.10

# Set the working directory
WORKDIR /app

# Copy the requirements file and install the dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the FastAPI app code
COPY app.py .

# Command to run the app using Uvicorn, which binds to the dynamic port
CMD ["python", "main.py"]