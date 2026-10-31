# API
This document describes the socket.io API of the insecure-chat-server application. It lists what messages are understood by the server and the client.


## Server messages
This section describes messages that can be received by a server.


### 'join'

    argument: string

The join request will start a new session for a client. The username should be passed as argument to the message. 

The server will respond by sending a '*login*' message to the client.

### 'new message'

    argument: {room:roomId, message: string}
Send a new message to a certain room on the server.

### 'request_direct_room'

    argument: {to: userId}

Requests to open a direct room with a specific user. Will respond to the client using '*update_room*'.

### 'add_channel'

    argument: {name: string, description: string, private: boolean}
Creates a new channel room, with the current user as only member. Will send an '*update_room*' message to the client. If the room is public (!private) then it will send an '*update_public_channels*' message to all users.

### 'join_channel'

    {id: roomId}
   Let's the current user join a certain channel. Will send an '*update_room*' message to the client. 

### 'leave_channel'

    {id: roomId}
   Let's the current user leave a certain channel. Will send an '*remove_room*' message to the client. 

### 'add_user_to_channel'

    {user: userId, channel: roomId}
   Let's a specific user join a certain channel. Will send an '*update_room*' message to the added user. 


## Client messages
This section describes messages that can be received by a client.

###  'login'

    {users: [{username: string, active:boolean}], rooms; [{id: roomId, name: string, ...}], publicChannels: [..roomList..]}
Received after performing a valid join. Contains information on users, joined rooms and public channels in the system.

### 'new message'

    {username: string, message: string, room: roomId, time: time, direct: boolean}
   
   Received when another user posts a message in a room containing the current user.

### 'user_state_change'

    {username: string, active: boolean}
   Received when another user goes online or offline.

### 'update_room'

    {room: roomId, moveto: boolean}
   Received when a certain room is updated. If the moveto boolean is set, the client will automatically jump to the channel.

### 'update_public_channels'

    {publicChannels: [..roomList..]}
   Received when a new public channel is created.

### 'remove_room'

    {room: roomId}
Received when a user is removed from a room.
