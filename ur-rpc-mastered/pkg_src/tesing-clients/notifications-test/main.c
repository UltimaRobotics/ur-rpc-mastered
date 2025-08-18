#include "notification_client.h"

int main() {
    printf("🚀 Enhanced MQTT Notification Client with Event Type Identification\n");
    printf("=====================================================================\n");
    printf("This client will identify notification event types and represent data\n");
    printf("according to the structs defined in notification_client.h\n");
    printf("=====================================================================\n\n");
    
    // Run the enhanced notification listener
    return run_notification_listener();
}