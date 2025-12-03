from fastapi import Response, status, HTTPException, Depends, APIRouter
from .. import models, schemas, oauth
from ..database import get_db
from sqlalchemy.orm import Session
from typing import List, Optional
from .. import models, schemas, oauth


router = APIRouter(
    prefix='/vote',
    tags=['Vote']
)


@router.post("/", status_code=status.HTTP_201_CREATED) 
def create_vote(vote: schemas.Vote, 
                db: Session = Depends(get_db), 
                current_user: int = Depends(oauth.get_current_user)):

    post = db.query(models.Post).filter(models.Post.id == vote.post_id).first()
    if not post:
        raise HTTPException(status_code=
                            status.HTTP_404_NOT_FOUND, 
                            detail=f"Post with id: {vote.post_id} does not exist")

    vote_query = db.query(models.Vote).filter(models.Vote.post_id == vote.post_id, 
                                      models.Vote.user_id == current_user.id)
    found_vote = vote_query.first()

    if vote.direction == 1:
        if found_vote:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, 
                                detail="Already upvoted")
        new_vote = models.Vote(post_id=vote.post_id, user_id=current_user.id)

        db.add(new_vote)
        db.commit()
        return {
            "status": "upvoted"
        }
    else:
        if not found_vote:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Not found")
        vote_query.delete(synchronize_session=False)
        db.commit()

        return {
            "status": "downvoted"
        }