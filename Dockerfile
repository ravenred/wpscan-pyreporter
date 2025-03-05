FROM python:3.13-slim

WORKDIR /wpscan-pyreporter

COPY . /wpscan-pyreporter

COPY ./requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8501

CMD ["streamlit", "run", "app.py"]
