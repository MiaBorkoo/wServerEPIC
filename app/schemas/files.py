from pydantic import BaseModel

class FileUploadRequest(BaseModel):
    owner_id: int # TODO: Should this be username or user_id from a session?
    name: str
    size: float
    encrypted_file: str
    integrity_hash: str

class FileShareRequest(BaseModel):
    owner_id: int # TODO: Should this be username or user_id from a session?
    recipient_id: int # TODO: Should this be username or user_id?
    file_id: str
    encrypted_file_key: str
    time_limit: int # TODO: Consider if time_limit should be a datetime or timedelta 