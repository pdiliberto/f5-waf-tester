FROM python:3.7-slim

# Create app directory
RUN mkdir -p /app
WORKDIR /app

# Bundle app source
COPY f5_waf_tester/ /app/
COPY f5-waf-tester.py requirements.txt /app/

# Install packages
RUN pip install -r requirements.txt

ENTRYPOINT [ "python", "f5-waf-tester.py" ]