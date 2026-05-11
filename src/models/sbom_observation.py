# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from sqlalchemy.orm import Mapped, relationship, mapped_column
from sqlalchemy import ForeignKey, Index

from ..extensions import Base, db
from ..models import SBOMDocument, Vulnerability, Package


class SBOMObservation(Base):
    """
    Represents an observation linking a vulnerability (and optionnally a package) to an SBOM document
    in order to store SBOM-specific information.
    """

    __tablename__ = "sbom_observation"
    __table_args__ = (
        Index("vuln_document_index", "vulnerability_id", "sbom_document_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column()
    """Key of the observation, unique for each vulnerability/package/sbom_document tuple (e.g. 'yocto description')"""
    description: Mapped[str] = mapped_column()
    """Description of the observation"""

    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"))
    package_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("packages.id"))
    sbom_document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sbom_documents.id"))

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="sbom_observations")
    package: Mapped[Package | None] = relationship(back_populates="sbom_observations")
    sbom_document: Mapped[SBOMDocument] = relationship(back_populates="sbom_observations")

    def __repr__(self) -> str:
        return (
            f"<SBOMObservation id={self.id} vulnerability_id={self.vulnerability_id} "
            f"package_id={self.package_id} sbom_document_id={self.sbom_document_id}>"
        )

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        vulnerability_id: str,
        sbom_document_id: uuid.UUID,
        key: str,
        description: str,
        package_id: uuid.UUID | None = None,
        commit: bool = True,
    ) -> "SBOMObservation":
        """Create a new SBOM observation, persist it and return it."""
        sbom_observation = SBOMObservation(
            vulnerability_id=vulnerability_id,
            sbom_document_id=sbom_document_id,
            package_id=package_id,
            key=key,
            description=description
        )
        db.session.add(sbom_observation)
        if commit:
            db.session.commit()
        else:
            db.session.flush()
        return sbom_observation

    @staticmethod
    def get_by_vuln(vulnerability_id: str) -> list["SBOMObservation"]:
        """Return all observations for the given vulnerability."""
        return list(db.session.execute(
            db.select(SBOMObservation).where(SBOMObservation.vulnerability_id == vulnerability_id)
        ).scalars().all())
