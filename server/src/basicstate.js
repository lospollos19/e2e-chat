module.exports = {
    setup: (Users, Rooms) => {
        if (!Rooms.getRoomByName('random'))
            Rooms.addRoom("random",  { forceMembership: true, description: "Random!" });
        if (!Rooms.getRoomByName('general'))
            Rooms.addRoom("general", { forceMembership: true, description: "interesting things" });
    }
}