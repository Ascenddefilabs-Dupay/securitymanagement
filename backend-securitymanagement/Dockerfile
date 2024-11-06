FROM python:3.11-slim

WORKDIR /backend-securitymanagement

COPY requirements.txt /backend-securitymanagement/
RUN pip3 install -r /backend-securitymanagement/requirements.txt

COPY . .


CMD ["python", "manage.py", "runserver", "0.0.0.0:8014"]
