#include <Havoc/Service.hpp>
#include <global.hpp>

uint64_t DemonMagicValue = 0xdeadbeef;

bool IsServiceAgent( uint64_t magic )
{
    for ( auto& agent : HavocX::Teamserver.ServiceAgents )
    {
        if ( magic == agent.MagicValue )
            return true;
    }
    return false;
}

bool IsDemonAgent( uint64_t magic )
{
    return ! IsServiceAgent( magic );
}
