from fastapi import FastAPI

app = FastAPI(title="Cybersecurity Evidence Investigator")


@app.get("/")
def root():
    return {"message": "Cybersecurity Evidence Investigator API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}