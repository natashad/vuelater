from later import db, User

if __name__ == '__main__':
    db.drop_all()
    db.create_all()