#include <Havoc/DBManager/DBManager.hpp>

bool HavocNamespace::HavocSpace::DBManager::AddHiddenSession( const QString& TeamserverName, const QString& SessionID )
{
    auto query = QSqlQuery();
    auto error = std::string();

    // Ensure the table exists (for existing databases)
    query.prepare(
        "CREATE TABLE IF NOT EXISTS \"HiddenSessions\" ( "
        "\"ID\" INTEGER PRIMARY KEY, "
        "\"TeamserverName\" TEXT, "
        "\"SessionID\" TEXT, "
        "UNIQUE(TeamserverName, SessionID) "
        ");"
    );
    query.exec();

    query.prepare( "INSERT OR IGNORE INTO HiddenSessions (TeamserverName, SessionID) VALUES(:TeamserverName, :SessionID)" );
    query.bindValue( ":TeamserverName", TeamserverName );
    query.bindValue( ":SessionID", SessionID );

    if ( ! query.exec() ) {
        error = query.lastError().text().toStdString();
        spdlog::error( "[DB] Failed to add hidden session: {}", error );
        return false;
    }

    return true;
}

bool HavocNamespace::HavocSpace::DBManager::RemoveHiddenSession( const QString& TeamserverName, const QString& SessionID )
{
    auto query = QSqlQuery();
    auto error = std::string();

    query.prepare( "DELETE FROM HiddenSessions WHERE TeamserverName = :TeamserverName AND SessionID = :SessionID" );
    query.bindValue( ":TeamserverName", TeamserverName );
    query.bindValue( ":SessionID", SessionID );

    if ( ! query.exec() ) {
        error = query.lastError().text().toStdString();
        spdlog::error( "[DB] Couldn't remove hidden session: {}", error );
        return false;
    }

    return true;
}

bool HavocNamespace::HavocSpace::DBManager::IsSessionHidden( const QString& TeamserverName, const QString& SessionID )
{
    auto query = QSqlQuery();
    auto error = std::string();

    // Ensure the table exists (for existing databases)
    query.prepare(
        "CREATE TABLE IF NOT EXISTS \"HiddenSessions\" ( "
        "\"ID\" INTEGER PRIMARY KEY, "
        "\"TeamserverName\" TEXT, "
        "\"SessionID\" TEXT, "
        "UNIQUE(TeamserverName, SessionID) "
        ");"
    );
    query.exec();

    query.prepare( "SELECT COUNT(*) FROM HiddenSessions WHERE TeamserverName = :TeamserverName AND SessionID = :SessionID" );
    query.bindValue( ":TeamserverName", TeamserverName );
    query.bindValue( ":SessionID", SessionID );

    if ( ! query.exec() ) {
        error = query.lastError().text().toStdString();
        spdlog::error( "[DB] Couldn't query hidden sessions: {}", error );
        return false;
    }

    if ( query.next() ) {
        return query.value(0).toInt() > 0;
    }

    return false;
}

vector<QString> HavocNamespace::HavocSpace::DBManager::GetHiddenSessions( const QString& TeamserverName )
{
    auto List  = vector<QString>();
    auto query = QSqlQuery();
    auto error = std::string();

    // Ensure the table exists (for existing databases)
    query.prepare(
        "CREATE TABLE IF NOT EXISTS \"HiddenSessions\" ( "
        "\"ID\" INTEGER PRIMARY KEY, "
        "\"TeamserverName\" TEXT, "
        "\"SessionID\" TEXT, "
        "UNIQUE(TeamserverName, SessionID) "
        ");"
    );
    query.exec();

    query.prepare( "SELECT SessionID FROM HiddenSessions WHERE TeamserverName = :TeamserverName" );
    query.bindValue( ":TeamserverName", TeamserverName );

    if ( ! query.exec() ) {
        error = query.lastError().text().toStdString();
        spdlog::error( "[DB] Couldn't query hidden sessions: {}", error );
        return List;
    }

    while ( query.next() )
        List.push_back( query.value("SessionID").toString() );

    return List;
}
