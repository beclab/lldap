use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::domain::types::{LoginRecord, UserId};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq,Serialize, Deserialize)]
#[sea_orm(table_name = "login_record")]
pub struct Model {
    #[sea_orm(
        primary_key,
        unique,
        auto_increment = true,
        column_name = "id"
    )]
    #[serde(skip_deserializing)]
    pub id: i32,

    #[sea_orm(
        column_name = "user_id",
    )]
    pub user_id: UserId,

    #[sea_orm(
        column_name = "success",
    )]
    pub success: bool,

    #[sea_orm(
        column_name = "reason"
    )]
    pub reason: String,

    #[sea_orm(
        column_name = "source_ip"
    )]
    pub source_ip: String,

    #[sea_orm(
        column_name = "user_agent"
    )]
    pub user_agent: String,

    #[sea_orm(
        column_name = "creation_date"
    )]
    pub creation_date: chrono::NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::UserId",
        on_delete = "Cascade"
    )]
    Users,
}
impl Related<super::users::Entity> for Entity  {
    fn to() -> RelationDef {
        Relation::Users.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for LoginRecord {
    fn from(model: Model) -> Self {
        LoginRecord {
            user_id: model.user_id,
            success: model.success,
            reason: model.reason,
            source_ip: model.source_ip,
            user_agent: model.user_agent,
            creation_date: model.creation_date,
        }
    }
}