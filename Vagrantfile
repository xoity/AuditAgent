Vagrant.configure("2") do |config|
  config.vm.box = "generic/alpine318"

  # Share the repo so guest tests run against the live working tree.
  config.vm.synced_folder ".", "/vagrant", type: "rsync",
    rsync__exclude: [".venv", ".git", "build", "dist", "__pycache__"]

  config.vm.provider "vmware_desktop" do |vmware|
    vmware.linked_clone = false
    vmware.gui = true

    # Add this line to disable 3D acceleration
    vmware.vmx["mks.enable3d"] = "FALSE"
  end
end
