import sqlalchemy as db
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from MSP import Request
from config import db as dbconf

Base = declarative_base()

association_table = db.Table(
    "Request_Vuln_assoc",
    Base.metadata,
    db.Column("request_id", db.Integer, db.ForeignKey("modsec.requests.id")),
    db.Column("vuln_id", db.Integer, db.ForeignKey("modsec.vulns.id"))
)

class Requests(Base):
    __tablename__ = "requests"
    __table_args__ = {"schema": "modsec"}

    id = db.Column(db.Integer, unique=True, primary_key=True, nullable=False)

    uri = db.Column(db.String(500), nullable=False)
    host = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    protocol = db.Column(db.String(100), nullable=False)
    ts = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Integer, nullable=False)

    vulns = db.orm.relationship(
        "Vulns",
        secondary=association_table,
        backref="request"
    )


class Vulns(Base):
    __tablename__ = "vulns"
    __table_args__ = {"schema": "modsec"}

    id = db.Column(db.Integer, unique=True, primary_key=True, nullable=False)
    desc = db.Column(db.String(2500), nullable=False)

engine = db.create_engine(f"postgresql://{dbconf['user']}:{dbconf['pwd']}@{dbconf['host']}:{dbconf['port']}/{dbconf['db']}")
engine.connect()
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

def CommitRequest(req : Request) -> None:
    sess = Session()
    r = Requests(
        uri = req.uri,
        host = req.host,
        method = req.method,
        protocol = req.protocol,
        ts = req.ts,
        status = int(req.result)
    )

    vs = set()

    for vuln in req.vulns:
        v = Vulns(
            id = vuln.id,
            desc = vuln.desc
        )
        exists = sess.query(Vulns).filter_by(id=v.id).first()
        if v.id not in vs:
            r.vulns.append(v)
            vs.add(v.id)
            if not exists:
                sess.add(v)

    sess.add(r)
    sess.commit()
