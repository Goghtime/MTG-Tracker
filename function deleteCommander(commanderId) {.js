    function deleteCommander(commanderId) {
    var csrfToken = $('meta[name="csrf-token"]').attr('content');
    
    $.ajax({
        url: '/delete_commander/' + commanderId,
        type: 'POST',
        headers: {
            'X-CSRFToken': csrfToken
        },
        success: function(response) {
            alert('Commander deleted successfully!');
            location.reload(); // Reload the page
        },
        error: function(error) {
            console.log(error);
        }
    });