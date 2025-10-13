package com.dua3.license.app;

import com.dua3.utility.data.Image;
import com.dua3.utility.fx.FxImage;
import com.dua3.utility.fx.FxImageUtil;
import com.dua3.utility.fx.FxUtil;
import com.dua3.utility.fx.controls.Dialogs;
import com.dua3.utility.lang.LangUtil;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.image.ImageView;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

public class KeyStoreManager extends Application {

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        var root = new StackPane(new Label("Hello, JavaFX 21!"));
        primaryStage.setScene(new Scene(root, 320, 240));
        primaryStage.setTitle("Minimal JavaFX 21 App");
        primaryStage.show();

        ButtonType btnNew = new ButtonType("New", ButtonBar.ButtonData.OK_DONE);
        ButtonType btnOpen = new ButtonType("Open", ButtonBar.ButtonData.OTHER);

        // add dialog
        FxImage logo = (FxImage) FxImageUtil.getInstance().load(LangUtil.getResourceURL(getClass(), "/com/dua3/license/app/Keytool-256.png"));
        Dialogs.input(primaryStage)
                .title("Select Keystore")
                .node("logo", new StackPane(new ImageView(logo.fxImage())))
                .showAndWait();
    }

}
