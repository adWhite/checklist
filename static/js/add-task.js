(function($) {
  var projectId = $('.project-title').data('id'),
    $addTask = $('.add-task'),
    url = "/task/add";

  $addTask.on('submit', function(e) {
    e.preventDefault(); 

    var $this = $(this),
      taskTitle = $this.find('.task-title').val();

    if (taskTitle) {
      $.ajax({
        url: url,
        type: 'POST',
        dataType: 'JSON',
        data: { projectId: projectId, title: taskTitle, author: currentUser},
        success: function(data) {
          location.href = location.href;
        },
        error: function(data) {
          console.log(data);       
        }
      });
    } else {
      throw "No title";
    }
  });
})(jQuery);
