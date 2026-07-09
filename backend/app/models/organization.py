"""Organization and commercial account foundations."""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class Organization(Base):
    """Commercial account boundary above one or more workspaces."""

    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    workspaces = relationship("Workspace", back_populates="organization")
    memberships = relationship("OrganizationMembership", back_populates="organization")
    billing_accounts = relationship("BillingAccount", back_populates="organization")
    subscriptions = relationship("Subscription", back_populates="organization")
    entitlements = relationship("Entitlement", back_populates="organization")

    __table_args__ = (Index("ix_organizations_active_slug", "active", "slug"),)

    def __repr__(self):
        return f"<Organization {self.slug}>"


class OrganizationMembership(Base):
    """User role assignment across an organization."""

    __tablename__ = "organization_memberships"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(String(50), nullable=False, index=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="memberships")
    user = relationship("User")

    __table_args__ = (
        Index(
            "ix_organization_memberships_org_user",
            "organization_id",
            "user_id",
            unique=True,
        ),
        Index("ix_organization_memberships_org_role", "organization_id", "role"),
    )

    def __repr__(self):
        return f"<OrganizationMembership organization={self.organization_id} user={self.user_id}>"


class Plan(Base):
    """Commercial or self-hosted entitlement bundle."""

    __tablename__ = "plans"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(80), unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    billing_mode = Column(String(50), nullable=False, index=True)
    public = Column(Boolean, default=False, nullable=False, index=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    monthly_price_cents = Column(Integer, nullable=True)
    annual_price_cents = Column(Integer, nullable=True)
    currency = Column(String(3), default="EUR", nullable=False)
    included_sending_domains = Column(Integer, nullable=True)
    included_message_volume = Column(Integer, nullable=True)
    included_users = Column(Integer, nullable=True)
    retention_days = Column(Integer, nullable=True)
    features = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    subscriptions = relationship("Subscription", back_populates="plan")

    def __repr__(self):
        return f"<Plan {self.code}>"


class BillingAccount(Base):
    """Billing destination for direct, reseller, or self-hosted subscriptions."""

    __tablename__ = "billing_accounts"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    billing_mode = Column(String(50), nullable=False, index=True)
    status = Column(String(50), default="active", nullable=False, index=True)
    provider_id = Column(String(120), nullable=True, index=True)
    external_customer_id = Column(String(120), nullable=True, index=True)
    stripe_customer_id = Column(String(120), nullable=True, index=True)
    invoice_delivery_mode = Column(String(50), nullable=False, default="internal")
    billing_contact_email = Column(String(255), nullable=True)
    tax_reference = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="billing_accounts")
    subscriptions = relationship("Subscription", back_populates="billing_account")

    __table_args__ = (Index("ix_billing_accounts_org_mode", "organization_id", "billing_mode"),)

    def __repr__(self):
        return f"<BillingAccount organization={self.organization_id} mode={self.billing_mode}>"


class Subscription(Base):
    """Current or historical plan subscription for an organization."""

    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=False, index=True)
    billing_account_id = Column(
        Integer, ForeignKey("billing_accounts.id"), nullable=True, index=True
    )
    billing_mode = Column(String(50), nullable=False, index=True)
    status = Column(String(50), default="active", nullable=False, index=True)
    current_period_start = Column(DateTime, nullable=True, index=True)
    current_period_end = Column(DateTime, nullable=True, index=True)
    stripe_subscription_id = Column(String(120), nullable=True, unique=True, index=True)
    external_subscription_id = Column(String(120), nullable=True, index=True)
    external_product_code = Column(String(120), nullable=True)
    monthly_price_cents = Column(Integer, nullable=True)
    canceled_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="subscriptions")
    plan = relationship("Plan", back_populates="subscriptions")
    billing_account = relationship("BillingAccount", back_populates="subscriptions")
    entitlements = relationship("Entitlement", back_populates="subscription")

    __table_args__ = (
        Index("ix_subscriptions_org_status", "organization_id", "status"),
        Index("ix_subscriptions_external", "billing_mode", "external_subscription_id"),
    )

    def __repr__(self):
        return f"<Subscription organization={self.organization_id} status={self.status}>"


class Entitlement(Base):
    """Normalized feature or limit granted to an organization."""

    __tablename__ = "entitlements"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), nullable=True, index=True)
    key = Column(String(120), nullable=False, index=True)
    value = Column(String(255), nullable=False)
    source = Column(String(50), default="system", nullable=False, index=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    effective_from = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="entitlements")
    subscription = relationship("Subscription", back_populates="entitlements")

    __table_args__ = (Index("ix_entitlements_org_key_active", "organization_id", "key", "active"),)

    def __repr__(self):
        return f"<Entitlement organization={self.organization_id} key={self.key}>"


class UsageRecord(Base):
    """Metered usage that can feed billing or provider invoicing."""

    __tablename__ = "usage_records"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=True, index=True)
    metric = Column(String(120), nullable=False, index=True)
    quantity = Column(Integer, nullable=False)
    unit = Column(String(50), nullable=False)
    period_start = Column(DateTime, nullable=False, index=True)
    period_end = Column(DateTime, nullable=False, index=True)
    idempotency_key = Column(String(160), nullable=False, unique=True, index=True)
    source = Column(String(50), default="system", nullable=False, index=True)
    external_customer_id = Column(String(120), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    organization = relationship("Organization")
    workspace = relationship("Workspace")

    __table_args__ = (
        Index("ix_usage_records_org_metric_period", "organization_id", "metric", "period_start"),
    )

    def __repr__(self):
        return f"<UsageRecord organization={self.organization_id} metric={self.metric}>"


class ProviderIntegration(Base):
    """External ISP/hosting-management or billing-system integration."""

    __tablename__ = "provider_integrations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    provider_type = Column(String(80), nullable=False, index=True)
    status = Column(String(50), default="planned", nullable=False, index=True)
    external_provider_id = Column(String(120), nullable=True, index=True)
    scopes = Column(Text, nullable=True)
    callback_url = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization")

    __table_args__ = (Index("ix_provider_integrations_type_status", "provider_type", "status"),)

    def __repr__(self):
        return f"<ProviderIntegration {self.provider_type} {self.name}>"


class BillingEvent(Base):
    """Auditable billing lifecycle event without storing full provider payloads."""

    __tablename__ = "billing_events"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), nullable=True, index=True)
    billing_mode = Column(String(50), nullable=False, index=True)
    event_type = Column(String(120), nullable=False, index=True)
    provider_id = Column(String(120), nullable=True, index=True)
    external_event_id = Column(String(160), nullable=True, index=True)
    status = Column(String(50), default="received", nullable=False, index=True)
    payload_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    organization = relationship("Organization")
    subscription = relationship("Subscription")

    __table_args__ = (
        Index("ix_billing_events_provider_event", "provider_id", "external_event_id"),
    )

    def __repr__(self):
        return f"<BillingEvent {self.billing_mode} {self.event_type}>"
